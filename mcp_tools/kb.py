import numpy as np
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any, Optional
import faiss
import sqlite3
import json
from datetime import datetime
from app.models import LogChunk

class KnowledgeBase:
    def __init__(self, faiss_index_path: str, sqlite_path: str):
        self.faiss_index_path = faiss_index_path
        self.sqlite_path = sqlite_path
        self.model = SentenceTransformer('all-MiniLM-L6-v2')  # all-MiniLM-L6-v2
        self.dimension = 384  # vector_dim=384
        self.chunk_size = 1500  # chunk=1500 chars
        self.chunk_overlap = 200  # overlap=200
        self.index = None
        self.conn = None
        self._init_storage()
    
    def _init_storage(self):
        """Initialize FAISS index and SQLite database"""
        try:
            self.index = faiss.read_index(f"{self.faiss_index_path}.index")
        except:
            self.index = faiss.IndexFlatIP(self.dimension)  # faiss=IndexFlatIP
        
        self.conn = sqlite3.connect(self.sqlite_path)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS chunks (
                id TEXT PRIMARY KEY,
                content TEXT,
                metadata TEXT,
                timestamp TEXT
            )
        ''')
        self.conn.commit()
    
    async def upsert(self, chunks: List[LogChunk]) -> int:
        """Store chunks with embeddings in FAISS and metadata in SQLite"""
        if not chunks:
            return 0
        
        contents = [chunk.content for chunk in chunks]
        embeddings = self.model.encode(contents)
        
        # Add to FAISS
        embeddings_normalized = embeddings / np.linalg.norm(embeddings, axis=1, keepdims=True)
        self.index.add(embeddings_normalized.astype('float32'))
        
        # Save FAISS index
        faiss.write_index(self.index, f"{self.faiss_index_path}.index")
        
        # Store metadata in SQLite
        for chunk, embedding in zip(chunks, embeddings):
            chunk.embedding = embedding.tolist()
            self.conn.execute(
                'INSERT OR REPLACE INTO chunks (id, content, metadata, timestamp) VALUES (?, ?, ?, ?)',
                (chunk.id, chunk.content, json.dumps(chunk.metadata), chunk.timestamp.isoformat())
            )
        
        self.conn.commit()
        return len(chunks)
    
    async def search(self, query: str, k: int = 10) -> List[Dict[str, Any]]:
        """Search for similar chunks using vector similarity"""
        if self.index.ntotal == 0:
            return []
        
        query_embedding = self.model.encode([query])
        query_embedding_normalized = query_embedding / np.linalg.norm(query_embedding, axis=1, keepdims=True)
        
        scores, indices = self.index.search(query_embedding_normalized.astype('float32'), k)
        
        results = []
        cursor = self.conn.cursor()
        
        for score, idx in zip(scores[0], indices[0]):
            if idx >= 0:  # Valid index
                cursor.execute('SELECT * FROM chunks WHERE rowid = ?', (int(idx) + 1,))
                row = cursor.fetchone()
                if row:
                    results.append({
                        'id': row[0],
                        'content': row[1],
                        'metadata': json.loads(row[2]),
                        'timestamp': row[3],
                        'score': float(score)
                    })
        
        return results
    
    def get_total_chunks(self) -> int:
        """Get total number of indexed chunks"""
        return self.index.ntotal if self.index else 0
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

kb = None

def get_kb():
    global kb
    if kb is None:
        kb = KnowledgeBase("storage/faiss_index", "storage/db.sqlite")
    return kb