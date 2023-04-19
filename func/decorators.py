


def benchmark(func):
    import time
    from datetime import datetime

    def wrapper(*args, **kwargs):
        start = time.time()
        return_value = func(*args, **kwargs)
        end = time.time()
        print('[*] {} Время выполнения функции {}: {} секунд.'.format(datetime.now(), func.__name__, end-start))
        return return_value
    return wrapper

