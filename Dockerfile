FROM python:3.13-slim

# Install python requirements
WORKDIR /opt
COPY ./pyproject.toml /opt/pyproject.toml

RUN pip3 install --no-cache-dir poetry
RUN poetry config virtualenvs.create false
RUN poetry install --no-dev

# Copy code
COPY ./jwthenticator /opt/jwthenticator


EXPOSE 8080
ENTRYPOINT ["python3", "-m", "jwthenticator.server"]
