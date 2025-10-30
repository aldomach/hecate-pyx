"""
Pool de conexiones para reutilización eficiente.
"""
import pyodbc
import threading
import time
from typing import Dict, Optional, Any
from queue import Queue, Empty
from contextlib import contextmanager

from ..core.config import POOL_SIZE, POOL_MAX_OVERFLOW
from ..core.exceptions import ConnectionError


class ConnectionPool:
    """Pool de conexiones reutilizables para SQL Server."""
    
    def __init__(
        self,
        server_config: Dict[str, Any],
        connector,
        master_password: str,
        pool_size: int = POOL_SIZE,
        max_overflow: int = POOL_MAX_OVERFLOW,
        timeout: int = 30
    ):
        """
        Args:
            server_config: Configuración del servidor
            connector: DatabaseConnector instance
            master_password: Contraseña maestra
            pool_size: Tamaño inicial del pool
            max_overflow: Conexiones adicionales máximas
            timeout: Timeout para obtener conexión del pool
        """
        self.server_config = server_config
        self.connector = connector
        self.master_password = master_password
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.timeout = timeout
        
        # Pool de conexiones disponibles
        self.pool: Queue = Queue(maxsize=pool_size + max_overflow)
        self.active_connections: Dict[int, pyodbc.Connection] = {}
        self.created_connections = 0
        self.lock = threading.Lock()
        
        # Crear conexiones iniciales
        self._initialize_pool()
    
    def _initialize_pool(self):
        """Crear conexiones iniciales en el pool."""
        for _ in range(self.pool_size):
            try:
                conn = self._create_connection()
                self.pool.put(conn)
                self.created_connections += 1
            except Exception as e:
                # Si no se puede crear conexión inicial, continuar
                print(f"Warning: Could not create initial connection: {e}")
                break
    
    def _create_connection(self) -> pyodbc.Connection:
        """Crear nueva conexión."""
        return self.connector.connect(
            self.server_config,
            self.master_password
        )
    
    def _is_connection_valid(self, conn: pyodbc.Connection) -> bool:
        """Verificar si una conexión sigue siendo válida."""
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            return True
        except Exception:
            return False
    
    def get_connection(self) -> pyodbc.Connection:
        """
        Obtener conexión del pool.
        
        Returns:
            Conexión válida
            
        Raises:
            ConnectionError: Si no se puede obtener conexión
        """
        with self.lock:
            # Intentar obtener conexión del pool
            try:
                conn = self.pool.get_nowait()
                
                # Verificar que la conexión sigue válida
                if self._is_connection_valid(conn):
                    conn_id = id(conn)
                    self.active_connections[conn_id] = conn
                    return conn
                else:
                    # Conexión inválida, crear nueva
                    conn.close()
                    self.created_connections -= 1
            except Empty:
                pass
            
            # Si no hay conexiones o son inválidas, crear nueva
            if self.created_connections < (self.pool_size + self.max_overflow):
                try:
                    conn = self._create_connection()
                    self.created_connections += 1
                    conn_id = id(conn)
                    self.active_connections[conn_id] = conn
                    return conn
                except Exception as e:
                    raise ConnectionError(f"Could not create new connection: {e}")
            
            # Pool lleno, esperar por conexión disponible
            try:
                conn = self.pool.get(timeout=self.timeout)
                if self._is_connection_valid(conn):
                    conn_id = id(conn)
                    self.active_connections[conn_id] = conn
                    return conn
                else:
                    conn.close()
                    self.created_connections -= 1
                    raise ConnectionError("No valid connections available")
            except Empty:
                raise ConnectionError("Timeout waiting for connection from pool")
    
    def return_connection(self, conn: pyodbc.Connection):
        """
        Devolver conexión al pool.
        
        Args:
            conn: Conexión a devolver
        """
        with self.lock:
            conn_id = id(conn)
            
            if conn_id in self.active_connections:
                del self.active_connections[conn_id]
                
                # Verificar que la conexión sigue válida
                if self._is_connection_valid(conn):
                    try:
                        # Rollback cualquier transacción pendiente
                        conn.rollback()
                        self.pool.put_nowait(conn)
                    except Exception:
                        # Pool lleno, cerrar conexión
                        conn.close()
                        self.created_connections -= 1
                else:
                    # Conexión inválida, cerrarla
                    conn.close()
                    self.created_connections -= 1
    
    @contextmanager
    def connection(self):
        """
        Context manager para usar conexiones del pool.
        
        Usage:
            with pool.connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
        """
        conn = self.get_connection()
        try:
            yield conn
        finally:
            self.return_connection(conn)
    
    def close_all(self):
        """Cerrar todas las conexiones del pool."""
        with self.lock:
            # Cerrar conexiones activas
            for conn in self.active_connections.values():
                try:
                    conn.close()
                except Exception:
                    pass
            self.active_connections.clear()
            
            # Cerrar conexiones en el pool
            while not self.pool.empty():
                try:
                    conn = self.pool.get_nowait()
                    conn.close()
                except Exception:
                    pass
            
            self.created_connections = 0
    
    def get_stats(self) -> Dict[str, int]:
        """Obtener estadísticas del pool."""
        with self.lock:
            return {
                'pool_size': self.pool.qsize(),
                'active_connections': len(self.active_connections),
                'total_created': self.created_connections,
                'max_size': self.pool_size + self.max_overflow
            }


class PoolManager:
    """Gestor global de pools de conexión."""
    
    def __init__(self):
        self.pools: Dict[str, ConnectionPool] = {}
        self.lock = threading.Lock()
    
    def get_pool(
        self,
        server_name: str,
        server_config: Dict[str, Any],
        connector,
        master_password: str
    ) -> ConnectionPool:
        """
        Obtener o crear pool para un servidor.
        
        Args:
            server_name: Nombre del servidor
            server_config: Configuración del servidor
            connector: DatabaseConnector instance
            master_password: Contraseña maestra
            
        Returns:
            Pool de conexiones
        """
        with self.lock:
            if server_name not in self.pools:
                self.pools[server_name] = ConnectionPool(
                    server_config,
                    connector,
                    master_password
                )
            return self.pools[server_name]
    
    def close_pool(self, server_name: str):
        """Cerrar pool de un servidor específico."""
        with self.lock:
            if server_name in self.pools:
                self.pools[server_name].close_all()
                del self.pools[server_name]
    
    def close_all_pools(self):
        """Cerrar todos los pools."""
        with self.lock:
            for pool in self.pools.values():
                pool.close_all()
            self.pools.clear()


# Instancia global del gestor de pools
pool_manager = PoolManager()
