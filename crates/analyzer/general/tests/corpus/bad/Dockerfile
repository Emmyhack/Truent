# EXPECT: gen_docker_root_user
# EXPECT: gen_docker_unpinned_base
# EXPECT: gen_pipe_to_shell
FROM ubuntu:latest
RUN apt-get update && curl -sSL https://get.example.com/install.sh | sh
COPY app /app
CMD ["/app"]
