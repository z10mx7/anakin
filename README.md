# Anakin

A free and unlimited python tool.

## Installation

```bash
pip install anakin
```

## Usage

### Initialize directory structure

```bash
anakin init
```

Create directory structure in current directory:

```bash
anakin init --here
```

### Install LazyVim

```bash
anakin add nv
```

## Features

- Directory structure initialization
- LazyVim installation
- Various utility commands (base64, hash, uuid, etc.)

~/code
├── work/                 # Your 2 Employer Companies
│   ├── company-a/        # Employment 1
│   │   ├── mobile-app/   # (Flutter/RN)
│   │   └── backend-api/  # (Go/FastAPI)
│   └── company-b/        # Employment 2
│       ├── infra-k8s/    # (Kubernetes/Docker configs)
│       └── web-portal/   # (Next.js)
├── clients/              # Freelance/Contract work
│   ├── client-x/
│   │   └── pos-system/   # (PHP/Postgres)
│   └── client-y/
│       └── automation/   # (Python Selenium scripts)
├── personal/             # Your learning & hobby projects
│   ├── portfolio/
│   └── learn-rust/
|   └── cv/
├── freelance/ # freelance work
|   ├── client-name_project-name/   # (React/Next.js)
|   └── client-name_project-name/   # (Flutter/RN)
|── oss/   # open source contribution
|── shared/   # reusable , shared, boilerplates...
├── infra/   # all Dockerfiles, k8s yamls, nginx.conf, etc. I reuse
└── scripts/   # scripts for automation, backup, etc.
└── archive/   # old finished projects  
└── templates/   #  ready to use scripts/templates from internet
└── dotfiles/   # dotfiles for my system
└── playground/              # (or playground) Throwaway code, quick tests, tmp files
    └── test-nginx/

## License

MIT
