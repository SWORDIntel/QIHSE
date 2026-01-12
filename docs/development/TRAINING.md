# QIHSE Model Training Guide

This guide covers the training pipeline for QIHSE (Quantum-Inspired Hilbert Space Expansion) search models.

## Overview

QIHSE training involves multiple stages:
1. **Data Preparation**: Generate or load training datasets
2. **Model Initialization**: Set up quantum-inspired components
3. **Supervised Training**: Optimize RFF and parameter prediction
4. **ML Optimization**: Train Thompson sampling bandits
5. **Quantization Calibration**: Fine-tune for different precisions
6. **Evaluation**: Benchmark against standard datasets

## Quick Start

```bash
# Install dependencies
./build.sh deps

# Train model
source venv/bin/activate
python train_qihse_model.py --config config.yaml --experiment qihse_v1

# Evaluate results
python evaluate.py --model exported_model/ --benchmark sift
```

## Training Data

### Data Formats

QIHSE expects training data in the following formats:

#### Triplet Format (Primary)
```
query_vector, positive_vector, negative_vector, metadata
```

Where:
- `query_vector`: Input query embedding (float32 array)
- `positive_vector`: Similar vector to query (float32 array)
- `negative_vector`: Dissimilar vector to query (float32 array)
- `metadata`: Optional JSON metadata

#### Pairwise Format (Alternative)
```
query_vector, candidate_vector, relevance_score, metadata
```

### Synthetic Data Generation

For development and testing, QIHSE can generate synthetic training data:

```python
from qihse.data import generate_synthetic_triplets

# Generate 1M triplets for BERT-sized embeddings
triplets = generate_synthetic_triplets(
    num_samples=1_000_000,
    input_dim=768,  # BERT embedding size
    similarity_threshold=0.8,  # Minimum positive similarity
    dissimilarity_threshold=0.3  # Maximum negative similarity
)

# Save to disk
np.savez('training_data.npz',
         queries=triplets['queries'],
         positives=triplets['positives'],
         negatives=triplets['negatives'])
```

### Real Data Sources

#### MS MARCO
```bash
# Download and preprocess
wget https://msmarco.blob.core.windows.net/msmarcoranking/collectionandqueries.tar.gz
tar -xzf collectionandqueries.tar.gz

# Convert to QIHSE format
python prepare_data.py --dataset msmarco --output msmarco_triplets.npz
```

#### SIFT1M
```bash
# Download SIFT dataset
wget ftp://ftp.irisa.fr/local/texmex/corpus/sift.tar.gz
tar -xzf sift.tar.gz

# Generate triplets
python prepare_data.py --dataset sift --output sift_triplets.npz
```

## Model Configuration

### Core Parameters

```yaml
model:
  input_dim: 768          # Input vector dimensionality
  rff_features: 512       # Random Fourier features (trade-off: accuracy vs speed)
  kernel_type: "rbf"      # Kernel: "rbf", "laplacian", "cauchy"
  num_states: 10000       # Superposition capacity
  vector_dim: 128         # Per-state dimensionality
  grover_iterations: 8    # Maximum amplification rounds
```

### Training Parameters

```yaml
training:
  max_epochs: 100         # Training duration
  batch_size: 256         # GPU memory trade-off
  learning_rate: 0.001    # Initial LR (will be scheduled)
  margin: 0.2             # Triplet loss margin
  triplet_weight: 1.0     # Relative loss weights
  param_weight: 0.1
```

### Hardware Configuration

```yaml
hardware:
  cpu:
    enabled: true
    threads: 16
  npu:
    enabled: true
    device: "NPU"
  gpu:
    enabled: true
    device: 0
```

## Training Stages

### Stage 1: RFF Training

Train the Random Fourier Features for kernel approximation:

```python
# Freeze superposition and Grover components
model.rff.requires_grad_(True)
model.superposition.requires_grad_(False)
model.grover.requires_grad_(False)

# Train RFF with triplet loss
trainer.fit(model, train_dataloader)
```

**Convergence Criteria**:
- Triplet loss < 0.1
- Validation recall@10 > 0.85
- Training time: 10-20 epochs

### Stage 2: End-to-End Training

Train all components jointly:

```python
# Unfreeze all components
model.requires_grad_(True)

# Train with full loss
trainer.fit(model, train_dataloader)
```

**Convergence Criteria**:
- Combined loss stable for 5 epochs
- Validation metrics plateau
- No overfitting (train/val gap < 10%)

### Stage 3: ML Optimization

Train Thompson sampling bandits for parameter optimization:

```python
from qihse.optimization import ThompsonSamplingBandit

bandit = ThompsonSamplingBandit(
    arms=['FP32', 'FP16', 'INT8', 'CPU', 'NPU', 'GPU'],
    alpha=1.0, beta=1.0
)

# Optimize over multiple episodes
for episode in range(100):
    arm = bandit.select_arm()
    reward = evaluate_configuration(arm)
    bandit.update(arm, reward)
```

## Quantization Training

### Post-Training Quantization (PTQ)

```python
from qihse.quantization import quantize_model

# Quantize to different precisions
for precision in ['FP16', 'INT8', 'INT4']:
    quantized_model = quantize_model(
        model,
        precision=precision,
        calibration_loader=calibration_dataloader
    )

    # Fine-tune quantized model
    trainer.fit(quantized_model, fine_tune_dataloader)
```

### Quantization-Aware Training (QAT)

```python
# Enable quantization from start of training
model.enable_quantization_aware_training()

# Train with quantization noise
trainer.fit(model, train_dataloader)

# Export quantized model
model.export_quantized_model('qihse_int8.onnx')
```

## Evaluation and Benchmarking

### Standard Benchmarks

```python
from qihse.benchmark import BenchmarkSuite

suite = BenchmarkSuite([
    'sift1m', 'gist1m', 'msmarco', 'glove', 'deep1m'
])

results = suite.run(model, output_dir='benchmark_results/')
suite.generate_report(results)
```

### Custom Metrics

```python
from qihse.metrics import SearchMetrics

metrics = SearchMetrics()

for query, ground_truth in test_dataset:
    results = model.search(query, k=100)
    metrics.update(results, ground_truth)

# Generate comprehensive report
report = metrics.generate_report()
print(f"Recall@10: {report['recall@10']:.3f}")
print(f"NDCG@10: {report['ndcg@10']:.3f}")
```

## Hyperparameter Optimization

### Grid Search

```python
from sklearn.model_selection import ParameterGrid

param_grid = {
    'rff_features': [256, 512, 1024],
    'learning_rate': [1e-3, 1e-4, 1e-5],
    'margin': [0.1, 0.2, 0.5],
    'batch_size': [128, 256, 512]
}

best_score = 0
best_params = None

for params in ParameterGrid(param_grid):
    model = QIHSEModel(**params)
    trainer.fit(model, train_dataloader)

    score = evaluate_model(model)
    if score > best_score:
        best_score = score
        best_params = params
```

### Bayesian Optimization

```python
from skopt import gp_minimize

def objective(params):
    rff_features, lr, margin = params
    model = QIHSEModel(rff_features=int(rff_features),
                      learning_rate=lr, margin=margin)
    trainer.fit(model, train_dataloader)
    return -evaluate_model(model)  # Minimize negative recall

space = [(256, 1024), (1e-5, 1e-3), (0.1, 0.5)]
result = gp_minimize(objective, space, n_calls=50)
```

## Monitoring and Debugging

### Training Monitoring

```python
# Enable detailed logging
trainer = pl.Trainer(
    logger=pl.loggers.WandbLogger(project="qihse-training"),
    callbacks=[
        pl.callbacks.LearningRateMonitor(),
        pl.callbacks.ModelCheckpoint(monitor='val_recall@10'),
        pl.callbacks.EarlyStopping(monitor='val_recall@10', patience=10)
    ]
)
```

### Performance Profiling

```python
from torch.profiler import profile, record_function, ProfilerActivity

with profile(activities=[ProfilerActivity.CPU, ProfilerActivity.CUDA]) as prof:
    with record_function("model_inference"):
        results = model(batch)

prof.export_chrome_trace("trace.json")
```

### Memory Debugging

```python
# Monitor memory usage
trainer = pl.Trainer(
    callbacks=[
        pl.callbacks.Callback(),  # Custom memory monitoring
    ]
)

# Check for memory leaks
torch.cuda.memory_summary()
```

## Deployment Preparation

### Model Export

```python
# Export for C++ inference
model.export_for_inference('exported_model/')

# Generate deployment configuration
config = {
    'model_path': 'qihse_model.onnx',
    'precision': 'INT8',
    'device': 'AUTO',
    'batch_size': 16
}

with open('deployment_config.json', 'w') as f:
    json.dump(config, f)
```

### Performance Validation

```python
# Validate deployment performance
deployment_validator = DeploymentValidator(model_path='exported_model/')

# Test throughput
throughput = deployment_validator.measure_throughput()
assert throughput > 1000, f"Throughput too low: {throughput}"

# Test latency
latency = deployment_validator.measure_latency()
assert latency < 10.0, f"Latency too high: {latency}ms"

# Test accuracy
accuracy = deployment_validator.measure_accuracy()
assert accuracy > 0.9, f"Accuracy too low: {accuracy}"
```

## Troubleshooting

### Common Issues

#### Out of Memory
```
Solution: Reduce batch_size, use gradient accumulation
config['training']['batch_size'] = 64
config['training']['accumulate_grad_batches'] = 4
```

#### Poor Convergence
```
Solution: Adjust learning rate, increase model capacity
config['training']['learning_rate'] = 1e-4
config['model']['rff_features'] = 1024
```

#### Overfitting
```
Solution: Add regularization, early stopping
config['training']['weight_decay'] = 1e-4
config['training']['early_stopping']['patience'] = 10
```

### Performance Optimization

#### GPU Optimization
```python
# Enable mixed precision
trainer = pl.Trainer(precision=16)

# Use DataParallel for multi-GPU
model = nn.DataParallel(model)
```

#### CPU Optimization
```python
# Use MKL for Intel CPUs
import torch
torch.set_num_threads(16)  # Match CPU cores
```

## Advanced Training Techniques

### Curriculum Learning

```python
# Start with easy examples, gradually increase difficulty
curriculum_scheduler = CurriculumScheduler(
    stages=[
        {'difficulty': 'easy', 'epochs': 10},
        {'difficulty': 'medium', 'epochs': 20},
        {'difficulty': 'hard', 'epochs': 30}
    ]
)
```

### Knowledge Distillation

```python
# Train student model to mimic teacher
teacher_model = load_pretrained_teacher()
student_model = QIHSEModel(smaller_config)

distiller = KnowledgeDistiller(teacher_model, student_model)
distiller.train(train_dataloader)
```

### Self-Supervised Pretraining

```python
# Pretrain on unlabeled data
pretrain_model = QIHSEPretrainingModel()
pretrain_trainer.fit(pretrain_model, unlabeled_dataloader)

# Fine-tune on labeled data
model.load_pretrained_weights(pretrain_model)
trainer.fit(model, labeled_dataloader)
```

This training guide provides a comprehensive framework for developing high-performance QIHSE models. The quantum-inspired architecture combined with ML optimization enables breakthrough performance in similarity search applications.
