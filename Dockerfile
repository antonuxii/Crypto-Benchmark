# Dockerfile (for Mac)
# Add solver libraries to the docker image.
FROM aisiuk/inspect-tool-support:latest

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
	build-essential \
	cmake \
	&& rm -rf /var/lib/apt/lists/*

# Python deps
RUN python -m pip install --no-cache-dir --upgrade pip

RUN python -m pip install --no-cache-dir \
	pulp \
	ortools \
	z3-solver \
	pysmt \
	python-sat \
# All the above can be succesfully called by the model