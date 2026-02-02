"""
Embedding and Retrieval System for AI IR Agent
Uses local sentence-transformers for embeddings and ChromaDB for storage.
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

# These will be imported after installation
try:
    from sentence_transformers import SentenceTransformer
    import chromadb
    from chromadb.config import Settings
except ImportError:
    print("Installing required packages...")
    import subprocess
    subprocess.run(["pip", "install", "sentence-transformers", "chromadb"], check=True)
    from sentence_transformers import SentenceTransformer
    import chromadb
    from chromadb.config import Settings


@dataclass
class SearchResult:
    """A search result from the RAG system."""
    document_id: str
    title: str
    content: str
    source: str
    source_type: str
    score: float
    chunk_index: int = 0


class RAGSystem:
    """RAG system for IR/RE knowledge retrieval."""

    def __init__(
        self,
        corpus_dir: str = None,
        db_dir: str = None,
        model_name: str = "all-MiniLM-L6-v2",
        chunk_size: int = 1000,
        chunk_overlap: int = 200
    ):
        # Set directories
        base_dir = Path(__file__).parent.parent.parent
        self.corpus_dir = Path(corpus_dir) if corpus_dir else base_dir / "corpus"
        self.db_dir = Path(db_dir) if db_dir else base_dir / "chroma_db"

        # Initialize embedding model
        print(f"Loading embedding model: {model_name}")
        self.model = SentenceTransformer(model_name)

        # Initialize ChromaDB
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(path=str(self.db_dir))

        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name="ir_knowledge",
            metadata={"hnsw:space": "cosine"}
        )

        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def _chunk_text(self, text: str, doc_id: str) -> List[Dict]:
        """Split text into overlapping chunks."""
        chunks = []
        words = text.split()

        if len(words) <= self.chunk_size:
            return [{"text": text, "doc_id": doc_id, "chunk_index": 0}]

        start = 0
        chunk_index = 0

        while start < len(words):
            end = min(start + self.chunk_size, len(words))
            chunk_text = " ".join(words[start:end])

            chunks.append({
                "text": chunk_text,
                "doc_id": doc_id,
                "chunk_index": chunk_index
            })

            start += self.chunk_size - self.chunk_overlap
            chunk_index += 1

        return chunks

    def index_corpus(self, force_reindex: bool = False):
        """Index all documents in the corpus."""
        # Check if already indexed
        if self.collection.count() > 0 and not force_reindex:
            print(f"Corpus already indexed ({self.collection.count()} chunks). Use force_reindex=True to reindex.")
            return

        if force_reindex:
            # Delete existing collection and recreate
            self.client.delete_collection("ir_knowledge")
            self.collection = self.client.create_collection(
                name="ir_knowledge",
                metadata={"hnsw:space": "cosine"}
            )

        print("Indexing corpus...")

        # Load all documents
        documents = []
        for json_file in self.corpus_dir.glob("**/*.json"):
            try:
                with open(json_file) as f:
                    documents.append(json.load(f))
            except Exception as e:
                print(f"Error loading {json_file}: {e}")

        print(f"Found {len(documents)} documents")

        # Process and index each document
        all_chunks = []
        all_embeddings = []
        all_ids = []
        all_metadata = []

        for doc in documents:
            chunks = self._chunk_text(doc["content"], doc["id"])

            for chunk in chunks:
                chunk_id = f"{doc['id']}_{chunk['chunk_index']}"

                all_chunks.append(chunk["text"])
                all_ids.append(chunk_id)
                all_metadata.append({
                    "doc_id": doc["id"],
                    "title": doc["title"],
                    "source": doc["source"],
                    "source_type": doc["source_type"],
                    "chunk_index": chunk["chunk_index"]
                })

        # Generate embeddings in batches
        print(f"Generating embeddings for {len(all_chunks)} chunks...")
        batch_size = 32

        for i in range(0, len(all_chunks), batch_size):
            batch_texts = all_chunks[i:i + batch_size]
            batch_embeddings = self.model.encode(batch_texts).tolist()
            all_embeddings.extend(batch_embeddings)

            if (i + batch_size) % 100 == 0:
                print(f"  Processed {min(i + batch_size, len(all_chunks))}/{len(all_chunks)}")

        # Add to ChromaDB
        print("Adding to vector database...")
        self.collection.add(
            ids=all_ids,
            embeddings=all_embeddings,
            documents=all_chunks,
            metadatas=all_metadata
        )

        print(f"Indexed {len(all_chunks)} chunks from {len(documents)} documents")

    def search(self, query: str, n_results: int = 5, source_type: Optional[str] = None) -> List[SearchResult]:
        """
        Search the corpus for relevant documents.

        Args:
            query: The search query
            n_results: Number of results to return
            source_type: Optional filter by source type (blog, procedure, mitre, tool)

        Returns:
            List of SearchResult objects
        """
        # Generate query embedding
        query_embedding = self.model.encode(query).tolist()

        # Build where filter if source_type specified
        where_filter = None
        if source_type:
            where_filter = {"source_type": source_type}

        # Search
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            where=where_filter
        )

        # Convert to SearchResult objects
        search_results = []
        if results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                metadata = results["metadatas"][0][i]
                distance = results["distances"][0][i] if results["distances"] else 0

                # Convert distance to similarity score (cosine)
                score = 1 - distance

                search_results.append(SearchResult(
                    document_id=metadata["doc_id"],
                    title=metadata["title"],
                    content=results["documents"][0][i],
                    source=metadata["source"],
                    source_type=metadata["source_type"],
                    score=score,
                    chunk_index=metadata["chunk_index"]
                ))

        return search_results

    def get_context_for_query(self, query: str, max_tokens: int = 4000) -> str:
        """
        Get relevant context for a query, formatted for LLM consumption.

        Args:
            query: The user's query
            max_tokens: Approximate max tokens for context (rough estimate)

        Returns:
            Formatted context string
        """
        results = self.search(query, n_results=10)

        context_parts = []
        current_length = 0
        max_chars = max_tokens * 4  # Rough token to char estimate

        for result in results:
            entry = f"""
### {result.title} (Score: {result.score:.2f})
Source: {result.source_type}

{result.content}

---
"""
            if current_length + len(entry) > max_chars:
                break

            context_parts.append(entry)
            current_length += len(entry)

        if not context_parts:
            return "No relevant context found."

        return "## Relevant Knowledge Base Context\n\n" + "\n".join(context_parts)


def test_rag():
    """Test the RAG system."""
    print("Initializing RAG system...")
    rag = RAGSystem()

    print("\nIndexing corpus...")
    rag.index_corpus()

    print("\nTesting search queries...")

    queries = [
        "How do I analyze PowerShell malware?",
        "What tools should I use for PE analysis?",
        "How do I decode VBScript obfuscation?",
        "What are common persistence mechanisms?",
    ]

    for query in queries:
        print(f"\n{'='*60}")
        print(f"Query: {query}")
        print("="*60)

        results = rag.search(query, n_results=3)
        for i, result in enumerate(results, 1):
            print(f"\n{i}. {result.title} (Score: {result.score:.2f})")
            print(f"   Type: {result.source_type}")
            print(f"   Preview: {result.content[:200]}...")


if __name__ == "__main__":
    test_rag()
