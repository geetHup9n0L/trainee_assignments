Dockerfile:
```
FROM i386/ubuntu:16.04

USER root

RUN apt-get update && apt-get install -y \
    gdb git python3 python3-pip python3-dev \
    file strace ltrace patchelf vim tmux wget curl \
    build-essential libssl-dev libffi-dev gcc-multilib

RUN python3 -m pip install --upgrade "pip < 21.0" "setuptools < 45.0"

RUN python3 -m pip install pwntools==4.8.0

RUN wget -q -O /root/.gdbinit-gef.py https://github.com/hugsy/gef/raw/main/gef.py && \
    echo "source /root/.gdbinit-gef.py" >> /root/.gdbinit

RUN useradd -m ctf
COPY starbound /home/ctf/starbound
COPY flag.txt /home/ctf/flag.txt
RUN chmod +x /home/ctf/starbound && \
    cp /root/.gdbinit /home/ctf/.gdbinit && \
    cp /root/.gdbinit-gef.py /home/ctf/.gdbinit-gef.py && \
    chown -R ctf:ctf /home/ctf/

USER ctf
WORKDIR /home/ctf
```
Runs with:
```
docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn_env tmux
```
