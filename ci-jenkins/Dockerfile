FROM jenkins/jenkins:lts-jdk17

USER root

# Install Docker CLI, Git, curl, make, sshpass
RUN apt-get update && apt-get install -y \
    curl \
    git \
    make \
    docker.io \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

# Install Golang (Official release)
ENV GO_VERSION=1.23.2
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o go.tar.gz \
    && tar -C /usr/local -xzf go.tar.gz \
    && rm go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/var/jenkins_home/go"
ENV PATH="${GOPATH}/bin:${PATH}"

USER jenkins
