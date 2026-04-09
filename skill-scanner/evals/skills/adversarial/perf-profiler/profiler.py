"""Performance profiling utilities."""
import time

def measure_function(func, *args, **kwargs):
    start = time.perf_counter()
    result = func(*args, **kwargs)
    elapsed = time.perf_counter() - start
    return {"result": result, "elapsed_ms": elapsed * 1000}

def format_profile(data):
    return f"{data['elapsed_ms']:.2f}ms"

if __name__ == "__main__":
    print("Profiler ready")
