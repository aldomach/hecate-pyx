"""
Sistema de reintentos automáticos con exponential backoff.
"""
import time
import random
from typing import Callable, Any, Optional, Type, Tuple
from functools import wraps

from ..core.config import MAX_RETRY_ATTEMPTS, RETRY_DELAY
from ..core.exceptions import ConnectionError


class RetryHandler:
    """Manejador de reintentos con exponential backoff."""
    
    def __init__(
        self,
        max_attempts: int = MAX_RETRY_ATTEMPTS,
        base_delay: float = RETRY_DELAY,
        max_delay: float = 60.0,
        backoff_factor: float = 2.0,
        jitter: bool = True
    ):
        """
        Args:
            max_attempts: Número máximo de intentos
            base_delay: Delay inicial en segundos
            max_delay: Delay máximo en segundos
            backoff_factor: Factor de multiplicación para backoff
            jitter: Agregar variación aleatoria al delay
        """
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.jitter = jitter
    
    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """
        Determinar si se debe reintentar basado en la excepción.
        
        Args:
            exception: Excepción que se produjo
            attempt: Número de intento actual
            
        Returns:
            True si se debe reintentar
        """
        if attempt >= self.max_attempts:
            return False
        
        # Tipos de errores que justifican reintentar
        retryable_errors = [
            "timeout",
            "connection reset",
            "connection refused",
            "temporarily unavailable",
            "server is not ready",
            "deadlock",
            "lock timeout",
            "communication link failure"
        ]
        
        error_message = str(exception).lower()
        
        return any(error in error_message for error in retryable_errors)
    
    def calculate_delay(self, attempt: int) -> float:
        """
        Calcular delay para el siguiente intento.
        
        Args:
            attempt: Número de intento actual
            
        Returns:
            Delay en segundos
        """
        delay = self.base_delay * (self.backoff_factor ** attempt)
        delay = min(delay, self.max_delay)
        
        if self.jitter:
            # Agregar ±25% de variación aleatoria
            jitter_range = delay * 0.25
            delay += random.uniform(-jitter_range, jitter_range)
        
        return max(delay, 0)
    
    def retry(
        self,
        func: Callable,
        *args,
        retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,),
        **kwargs
    ) -> Any:
        """
        Ejecutar función con reintentos automáticos.
        
        Args:
            func: Función a ejecutar
            *args: Argumentos para la función
            retryable_exceptions: Tipos de excepciones que justifican reintentar
            **kwargs: Argumentos keyword para la función
            
        Returns:
            Resultado de la función
            
        Raises:
            Exception: La última excepción si todos los reintentos fallan
        """
        last_exception = None
        
        for attempt in range(self.max_attempts):
            try:
                return func(*args, **kwargs)
            
            except retryable_exceptions as e:
                last_exception = e
                
                if not self.should_retry(e, attempt):
                    break
                
                if attempt < self.max_attempts - 1:
                    delay = self.calculate_delay(attempt)
                    print(f"Retry attempt {attempt + 1}/{self.max_attempts} "
                          f"after {delay:.2f}s delay: {e}")
                    time.sleep(delay)
            
            except Exception as e:
                # Excepción no retryable
                raise e
        
        # Si llegamos aquí, todos los reintentos fallaron
        raise last_exception or Exception("All retry attempts failed")


def retry_on_failure(
    max_attempts: int = MAX_RETRY_ATTEMPTS,
    base_delay: float = RETRY_DELAY,
    retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,)
):
    """
    Decorador para agregar reintentos automáticos a una función.
    
    Args:
        max_attempts: Número máximo de intentos
        base_delay: Delay inicial en segundos
        retryable_exceptions: Tipos de excepciones que justifican reintentar
        
    Usage:
        @retry_on_failure(max_attempts=3, base_delay=1.0)
        def connect_to_database():
            # código que puede fallar
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            handler = RetryHandler(
                max_attempts=max_attempts,
                base_delay=base_delay
            )
            return handler.retry(
                func,
                *args,
                retryable_exceptions=retryable_exceptions,
                **kwargs
            )
        return wrapper
    return decorator


class CircuitBreaker:
    """
    Circuit breaker para evitar llamadas repetidas a servicios que fallan.
    
    Estados:
    - CLOSED: Normal, permite todas las llamadas
    - OPEN: Falla detectada, rechaza llamadas inmediatamente
    - HALF_OPEN: Probando si el servicio se recuperó
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        timeout: float = 60.0,
        expected_exception: Type[Exception] = Exception
    ):
        """
        Args:
            failure_threshold: Número de fallas antes de abrir el circuito
            timeout: Tiempo en segundos antes de intentar cerrar el circuito
            expected_exception: Tipo de excepción que cuenta como falla
        """
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Ejecutar función a través del circuit breaker.
        
        Args:
            func: Función a ejecutar
            *args: Argumentos para la función
            **kwargs: Argumentos keyword para la función
            
        Returns:
            Resultado de la función
            
        Raises:
            Exception: Si el circuito está abierto o la función falla
        """
        if self.state == "OPEN":
            if self._should_attempt_reset():
                self.state = "HALF_OPEN"
            else:
                raise ConnectionError("Circuit breaker is OPEN")
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        
        except self.expected_exception as e:
            self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Verificar si es tiempo de intentar resetear el circuito."""
        if self.last_failure_time is None:
            return True
        
        return time.time() - self.last_failure_time >= self.timeout
    
    def _on_success(self):
        """Manejar llamada exitosa."""
        self.failure_count = 0
        self.state = "CLOSED"
    
    def _on_failure(self):
        """Manejar falla en la llamada."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"


def with_circuit_breaker(
    failure_threshold: int = 5,
    timeout: float = 60.0,
    expected_exception: Type[Exception] = Exception
):
    """
    Decorador para agregar circuit breaker a una función.
    
    Usage:
        @with_circuit_breaker(failure_threshold=3, timeout=30.0)
        def risky_operation():
            # código que puede fallar repetidamente
            pass
    """
    breaker = CircuitBreaker(failure_threshold, timeout, expected_exception)
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            return breaker.call(func, *args, **kwargs)
        return wrapper
    return decorator
