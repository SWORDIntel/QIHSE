#!/bin/bash
#
# QIHSE Model Build Script
#
# Builds the QIHSE training pipeline and exports models for inference.
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
MODEL_DIR="${SCRIPT_DIR}"
BUILD_DIR="${MODEL_DIR}/build"
EXPORT_DIR="${MODEL_DIR}/exported_model"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."

    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi

    # Check pip
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 is required but not installed"
        exit 1
    fi

    # Check PyTorch
    if ! python3 -c "import torch; print(torch.__version__)" &> /dev/null; then
        log_warn "PyTorch not found, installing..."
        pip3 install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
    fi

    log_success "Dependencies check passed"
}

# Setup virtual environment
setup_venv() {
    log_info "Setting up virtual environment..."

    if [ ! -d "${MODEL_DIR}/venv" ]; then
        python3 -m venv "${MODEL_DIR}/venv"
    fi

    source "${MODEL_DIR}/venv/bin/activate"
    pip install --upgrade pip

    log_success "Virtual environment ready"
}

# Install dependencies
install_deps() {
    log_info "Installing Python dependencies..."

    source "${MODEL_DIR}/venv/bin/activate"
    pip install -r "${MODEL_DIR}/requirements.txt"

    log_success "Dependencies installed"
}

# Build C++ extensions (if any)
build_extensions() {
    log_info "Building C++ extensions..."

    # Create build directory
    mkdir -p "${BUILD_DIR}"
    cd "${BUILD_DIR}"

    # Configure with CMake (if applicable)
    if [ -f "${MODEL_DIR}/CMakeLists.txt" ]; then
        cmake "${MODEL_DIR}" \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="${MODEL_DIR}/install"
        make -j$(nproc)
        make install
    else
        log_info "No CMake configuration found, skipping C++ build"
    fi

    cd "${MODEL_DIR}"
    log_success "C++ extensions built"
}

# Validate configuration
validate_config() {
    log_info "Validating configuration..."

    if [ ! -f "${MODEL_DIR}/config.yaml" ]; then
        log_error "Configuration file config.yaml not found"
        exit 1
    fi

    # Basic YAML validation
    if command -v python3 &> /dev/null; then
        python3 -c "
import yaml
try:
    with open('${MODEL_DIR}/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    print('Configuration is valid YAML')
except Exception as e:
    print(f'Configuration validation failed: {e}')
    exit(1)
"
    fi

    log_success "Configuration validated"
}

# Run tests
run_tests() {
    log_info "Running tests..."

    source "${MODEL_DIR}/venv/bin/activate"

    # Run Python tests
    if [ -d "${MODEL_DIR}/tests" ]; then
        python3 -m pytest "${MODEL_DIR}/tests/" -v --tb=short
    else
        log_warn "No test directory found, skipping tests"
    fi

    log_success "Tests completed"
}

# Build Docker image
build_docker() {
    log_info "Building Docker image..."

    if [ -f "${MODEL_DIR}/Dockerfile" ]; then
        docker build -t qihse-model:latest "${MODEL_DIR}"
        log_success "Docker image built"
    else
        log_warn "No Dockerfile found, skipping Docker build"
    fi
}

# Main build function
main() {
    log_info "Starting QIHSE Model Build"
    log_info "Model Directory: ${MODEL_DIR}"
    log_info "Build Directory: ${BUILD_DIR}"

    check_dependencies
    setup_venv
    install_deps
    validate_config
    build_extensions
    run_tests
    build_docker

    log_success "QIHSE Model build completed successfully!"
    log_info "Next steps:"
    log_info "  1. Run training: source venv/bin/activate && python train_qihse_model.py --config config.yaml"
    log_info "  2. Run evaluation: python evaluate.py --model exported_model/"
    log_info "  3. Deploy model: see deployment/ directory"
}

# Parse command line arguments
case "${1:-all}" in
    "deps")
        check_dependencies
        setup_venv
        install_deps
        ;;
    "validate")
        validate_config
        ;;
    "test")
        run_tests
        ;;
    "docker")
        build_docker
        ;;
    "all")
        main
        ;;
    *)
        echo "Usage: $0 [deps|validate|test|docker|all]"
        echo "  deps     - Install dependencies"
        echo "  validate - Validate configuration"
        echo "  test     - Run tests"
        echo "  docker   - Build Docker image"
        echo "  all      - Full build (default)"
        exit 1
        ;;
esac
