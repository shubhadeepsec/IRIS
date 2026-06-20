# Installation

IRIS requires Python 3.9+.

## Clone the Repository
```bash
git clone https://github.com/malrobust/iris.git
cd iris
```

## Setup Virtual Environment
It is recommended to run IRIS inside a virtual environment.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## Install Dependencies
Install the package and its dependencies in editable mode:
```bash
pip install -e .
```

## Setup Environment
Create a `.env` file to store optional API keys:
```bash
cp .env.example .env
```
Edit `.env` and add any necessary keys (e.g., `HIBP_API_KEY`, `GITHUB_TOKEN`).

## Run
```bash
iris --help
```
