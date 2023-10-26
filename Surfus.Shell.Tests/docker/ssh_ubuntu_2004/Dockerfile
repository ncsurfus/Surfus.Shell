FROM ubuntu:20.04
RUN apt-get update -y && apt-get install -y openssh-server && apt-get clean
RUN mkdir -p /run/sshd
RUN useradd -m -d /home/ubuntu -s /bin/bash -p $(openssl passwd -1 testpassword) testuser
RUN sed -i "s/.*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication=yes/" /etc/ssh/sshd_config
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-o", "ListenAddress=0.0.0.0"]
