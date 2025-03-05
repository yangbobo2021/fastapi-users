FROM python:3.13 AS builder
RUN mkdir -p /app
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

FROM python:3.13-slim
ARG COMMIT_SHA=unknown
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin/ /usr/local/bin/
COPY . /app
RUN echo $COMMIT_SHA > /app/commit.txt
CMD [ "python3", "main.py" ]
