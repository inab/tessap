# docker-tes-proxy

A docker shim which submits commands to a GA4GH TES service.

## Introduction

The target from [EuroScienceGateway](https://galaxyproject.org/projects/esg/) T3.4
is that [WfExS-backend](https://github.com/inab/WfExS-backend) workflow
orchestrator uses [GA4GH TES](https://ga4gh.github.io/task-execution-schemas/docs/)
nodes for the computation of the
workflows. This is because T3.2 from ESG has created a GA4GH TES frontend
for Galaxy Pulsar nodes.

## Rationale
WfExS-backend delegates workflow executions to the most appropriate 
supported workflow engine: either [Nextflow](https://www.nextflow.io)
or [cwltool](https://cwltool.readthedocs.io). Although Nextflow supports
GA4GH TES in some degree, cwltool itself does not, and the same can happen
to other supported workflow engines in the future.

But, all these workflow engines share a common feature: all of them support
running their workflow steps using docker (when the workflow has been written
to do it so). So, the idea is replacing the original docker command
meanwhile the command line compatibility is kept.

## Currently subcommands being implemented

Each workflow engine depends on a subset of docker subcommands in order
to work properly.

| Implemented | Subcommand | Nextflow | cwltool |
|:-----------:|------------|:--------:|:-------:|
| :ballot_box_with_check: | `docker run` | :ballot_box_with_check: | :ballot_box_with_check: |
| :ballot_box_with_check: | `docker rm` | :ballot_box_with_check: | :black_square_button: |
| :ballot_box_with_check: | `docker stop` | :ballot_box_with_check: | :black_square_button: |
| :ballot_box_with_check: | `docker kill` | :ballot_box_with_check: | :black_square_button: |
| :ballot_box_with_check: | `docker ps` | :black_square_button: | :black_square_button: |
| :ballot_box_with_check: | `docker pull` | :black_square_button: | :ballot_box_with_check: |
| :heavy_exclamation_mark: | `docker stats` | :black_square_button: | :ballot_box_with_check: |
| :ballot_box_with_check: | `docker inspect` | :black_square_button: | :ballot_box_with_check: |
| :x: | `docker import` | :black_square_button: | :ballot_box_with_check: |
| :x: | `docker load` | :black_square_button: | :ballot_box_with_check: |
| :x: | `docker build` | :black_square_button: | :ballot_box_with_check: |

So, most of previous subcommands from `docker` are being implemented in order to mimic it,
so this shim can bypass the original one in order to forward commands
to a set up GA4GH TES service. As 

For other commands, the line is passed to the locally installed docker binary.

## Development/test environment (before integration with ESG)

1. Install this code.
   
   ```bash
   git clone https://github.com/inab/docker-tes-proxy.git
   cd docker-tes-proxy
   python3 -mvenv .full
   source .full/bin/activate
   pip install --upgrade pip wheel
   pip install -r requirements.txt
   ```

2. Download pre-compiled [funnel 0.11.0](https://github.com/ohsu-comp-bio/funnel/releases/tag/0.11.0)
   (choose the suitable one for your platform) or compile it.
   
   ```bash
   wget https://github.com/ohsu-comp-bio/funnel/releases/download/0.11.0/funnel-linux-amd64-0.11.0.tar.gz
   mkdir funnel-0.11.0
   tar -x -C funnel-0.11.0 -f funnel-linux-amd64-0.11.0.tar.gz
   ```
   
3. Start funnel with the configuration file available at [devel-config/funnel-config.yml](devel-config/funnel-config.yml).
   For instance:
   
   ```bash
   funnel-0.11.0/funnel server run -c devel-config/funnel-config.yml
   ```
   
   Remember that funnel itself uses docker, so you also need docker properly set up and running for that user.
   (i.e. the user must be included in `docker` group, and docker daemon needs to run).
   
4. Try some command which is properly implemented:
   
   ```bash
   python docker.py run --rm -ti ubuntu:22.04 ls /tmp
   ```

   ```bash
   python docker.py run -e VARIABLE=value --rm -ti ubuntu:22.04 env
   ```

   ```bash
   python docker.py run -v ./README.md:/SOME.md:ro --rm -ti ubuntu:22.04 md5sum /SOME.md
   ```

   ```bash
   python docker.py run -v ./README.md:/SOME.md:ro -v ./transferred.md:/tmp/OTHER.md --rm -ti ubuntu:22.04 cp /SOME.md /tmp/OTHER.md
   ```
