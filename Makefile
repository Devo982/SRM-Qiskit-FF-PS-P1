.PHONY: preflight test handshake pilot benchmark-a benchmark-b
preflight:
	python -m src.cli check

test:
	python -m pytest -q

handshake:
	python -m src.cli handshake --mode all

pilot:
	python -m src.benchmark --platform A --iterations 20 --warmup 5 --batches 1 --memory-reps 10

benchmark-a:
	python -m src.benchmark --platform A --iterations 1000 --warmup 100 --batches 5

benchmark-b:
	python -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5
