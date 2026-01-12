#!/usr/bin/env python3
"""
QIHSE Model Training Pipeline

Trains quantum-inspired search models with ML optimization for heterogeneous hardware.
"""

import argparse
import logging
import yaml
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import pytorch_lightning as pl
from pytorch_lightning.callbacks import ModelCheckpoint, EarlyStopping
from sklearn.metrics import recall_score, ndcg_score
import wandb
from pathlib import Path
import json
from datetime import datetime

# QIHSE Core Components
from qihse.core import QIHSEContext, QIHSESearch
from qihse.algorithms import RFFKernel, SuperpositionEncoder, GroverAmplifier
from qihse.optimization import ThompsonSamplingOptimizer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class QIHSEModel(pl.LightningModule):
    """PyTorch Lightning module for QIHSE model training."""

    def __init__(self, config):
        super().__init__()
        self.save_hyperparameters(config)

        # Core QIHSE components
        self.rff = RFFKernel(
            input_dim=config['model']['input_dim'],
            rff_features=config['model']['rff_features'],
            kernel_type=config['model']['kernel_type']
        )

        self.superposition = SuperpositionEncoder(
            num_states=config['model']['num_states'],
            vector_dim=config['model']['vector_dim']
        )

        self.grover = GroverAmplifier(
            max_iterations=config['model']['grover_iterations']
        )

        # ML optimization components
        self.optimizer = ThompsonSamplingOptimizer(
            n_arms=config['optimization']['num_arms'],
            alpha=config['optimization']['alpha'],
            beta=config['optimization']['beta']
        )

        # Neural network for parameter prediction
        self.parameter_predictor = nn.Sequential(
            nn.Linear(config['model']['input_dim'], 512),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, len(config['optimization']['parameter_dims']))
        )

        # Loss functions
        self.mse_loss = nn.MSELoss()
        self.bce_loss = nn.BCELoss()

    def forward(self, x):
        """Forward pass through QIHSE pipeline."""
        # RFF projection
        rff_features = self.rff(x)

        # Superposition encoding
        superposition_state = self.superposition(rff_features)

        # Grover amplification
        amplified_state = self.grover(superposition_state)

        # Parameter prediction for optimization
        parameters = self.parameter_predictor(x)

        return {
            'rff_features': rff_features,
            'superposition': superposition_state,
            'amplified': amplified_state,
            'parameters': parameters
        }

    def training_step(self, batch, batch_idx):
        """Training step with multi-task learning."""
        queries, positives, negatives, labels = batch

        # Forward pass
        query_output = self(queries)
        positive_output = self(positives)
        negative_output = self(negatives)

        # Compute similarities
        query_rff = query_output['rff_features']
        positive_rff = positive_output['rff_features']
        negative_rff = negative_output['rff_features']

        # Cosine similarity loss
        positive_sim = torch.cosine_similarity(query_rff, positive_rff, dim=-1)
        negative_sim = torch.cosine_similarity(query_rff, negative_rff, dim=-1)

        # Triplet loss: maximize positive sim, minimize negative sim
        triplet_loss = torch.relu(negative_sim - positive_sim + self.hparams['training']['margin'])
        triplet_loss = triplet_loss.mean()

        # Parameter prediction loss
        param_targets = self._generate_parameter_targets(queries, positives, labels)
        param_loss = self.mse_loss(query_output['parameters'], param_targets)

        # Total loss
        total_loss = (
            self.hparams['training']['triplet_weight'] * triplet_loss +
            self.hparams['training']['param_weight'] * param_loss
        )

        # Log metrics
        self.log('train_loss', total_loss)
        self.log('train_triplet_loss', triplet_loss)
        self.log('train_param_loss', param_loss)

        return total_loss

    def validation_step(self, batch, batch_idx):
        """Validation step with recall and NDCG metrics."""
        queries, positives, negatives, labels = batch

        # Forward pass
        query_output = self(queries)

        # Compute recall and NDCG
        recall_at_10 = self._compute_recall_at_k(query_output['rff_features'], positives, k=10)
        ndcg_at_10 = self._compute_ndcg_at_k(query_output['rff_features'], positives, k=10)

        self.log('val_recall@10', recall_at_10)
        self.log('val_ndcg@10', ndcg_at_10)

        return {
            'recall@10': recall_at_10,
            'ndcg@10': ndcg_at_10
        }

    def _generate_parameter_targets(self, queries, positives, labels):
        """Generate target parameters for ML optimization."""
        # Simplified parameter target generation
        batch_size = queries.size(0)
        num_params = len(self.hparams['optimization']['parameter_dims'])

        # Generate reasonable parameter targets based on query characteristics
        targets = torch.zeros(batch_size, num_params)

        # Example: precision based on query difficulty
        query_norms = torch.norm(queries, dim=-1)
        targets[:, 0] = torch.sigmoid(query_norms - 1.0)  # Precision selection

        # Device selection based on query complexity
        targets[:, 1] = torch.sigmoid((query_norms - 0.5) * 2)  # CPU vs GPU

        return targets

    def _compute_recall_at_k(self, query_features, positive_features, k=10):
        """Compute Recall@K metric."""
        # Simplified recall computation
        similarities = torch.cosine_similarity(
            query_features.unsqueeze(1),
            positive_features.unsqueeze(0),
            dim=-1
        )

        # Get top-k indices
        _, top_k_indices = similarities.topk(k, dim=-1)

        # For simplicity, assume first positive is relevant
        relevant_indices = torch.arange(query_features.size(0))

        # Compute recall
        recall = 0.0
        for i in range(query_features.size(0)):
            if relevant_indices[i] in top_k_indices[i]:
                recall += 1.0

        return recall / query_features.size(0)

    def _compute_ndcg_at_k(self, query_features, positive_features, k=10):
        """Compute NDCG@K metric."""
        # Simplified NDCG computation
        similarities = torch.cosine_similarity(
            query_features.unsqueeze(1),
            positive_features.unsqueeze(0),
            dim=-1
        )

        # Get top-k values
        top_k_values, _ = similarities.topk(k, dim=-1)

        # Compute DCG (simplified)
        dcg = torch.sum(top_k_values / torch.log2(torch.arange(1, k + 1) + 1), dim=-1)

        # Ideal DCG (perfect ranking)
        ideal_dcg = torch.sum(torch.ones_like(dcg) / torch.log2(torch.arange(1, k + 1) + 1), dim=-1)

        # NDCG
        ndcg = dcg / ideal_dcg

        return ndcg.mean()

    def configure_optimizers(self):
        """Configure optimizers and schedulers."""
        optimizer = torch.optim.AdamW(
            self.parameters(),
            lr=self.hparams['training']['learning_rate'],
            weight_decay=self.hparams['training']['weight_decay']
        )

        scheduler = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(
            optimizer,
            T_0=self.hparams['training']['scheduler_t0'],
            T_mult=self.hparams['training']['scheduler_t_mult']
        )

        return {
            'optimizer': optimizer,
            'lr_scheduler': {
                'scheduler': scheduler,
                'interval': 'epoch'
            }
        }


class QIHSEDataModule(pl.LightningDataModule):
    """Data module for QIHSE training data."""

    def __init__(self, config):
        super().__init__()
        self.config = config

    def setup(self, stage=None):
        """Setup datasets for training and validation."""
        # Generate synthetic training data
        train_data = self._generate_training_data(
            self.config['data']['train_samples'],
            self.config['model']['input_dim']
        )
        val_data = self._generate_training_data(
            self.config['data']['val_samples'],
            self.config['model']['input_dim']
        )

        self.train_dataset = TensorDataset(*train_data)
        self.val_dataset = TensorDataset(*val_data)

    def _generate_training_data(self, num_samples, input_dim):
        """Generate synthetic training data."""
        # Generate random queries
        queries = torch.randn(num_samples, input_dim)

        # Generate positive examples (similar to queries)
        positives = queries + torch.randn(num_samples, input_dim) * 0.1

        # Generate negative examples (dissimilar to queries)
        negatives = torch.randn(num_samples, input_dim)

        # Generate labels (for parameter prediction)
        labels = torch.randint(0, 2, (num_samples,))

        return queries, positives, negatives, labels

    def train_dataloader(self):
        return DataLoader(
            self.train_dataset,
            batch_size=self.config['training']['batch_size'],
            shuffle=True,
            num_workers=self.config['data']['num_workers']
        )

    def val_dataloader(self):
        return DataLoader(
            self.val_dataset,
            batch_size=self.config['training']['batch_size'],
            shuffle=False,
            num_workers=self.config['data']['num_workers']
        )


def main():
    """Main training function."""
    parser = argparse.ArgumentParser(description='Train QIHSE model')
    parser.add_argument('--config', type=str, required=True,
                       help='Path to configuration YAML file')
    parser.add_argument('--experiment', type=str, default='qihse_training',
                       help='Experiment name for logging')
    parser.add_argument('--checkpoint', type=str, default=None,
                       help='Path to checkpoint to resume training')

    args = parser.parse_args()

    # Load configuration
    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)

    # Setup logging
    if config.get('logging', {}).get('wandb', {}).get('enabled', False):
        wandb.init(
            project=config['logging']['wandb']['project'],
            name=args.experiment,
            config=config
        )

    # Create model
    model = QIHSEModel(config)

    # Create data module
    data_module = QIHSEDataModule(config)

    # Setup callbacks
    callbacks = []

    # Model checkpointing
    checkpoint_callback = ModelCheckpoint(
        dirpath=config['training']['checkpoint_dir'],
        filename='{epoch:02d}-{val_recall@10:.3f}',
        monitor='val_recall@10',
        mode='max',
        save_top_k=3
    )
    callbacks.append(checkpoint_callback)

    # Early stopping
    if config['training'].get('early_stopping', {}).get('enabled', False):
        early_stopping = EarlyStopping(
            monitor='val_recall@10',
            patience=config['training']['early_stopping']['patience'],
            mode='max'
        )
        callbacks.append(early_stopping)

    # Create trainer
    trainer = pl.Trainer(
        max_epochs=config['training']['max_epochs'],
        accelerator=config['training'].get('accelerator', 'auto'),
        devices=config['training'].get('devices', 'auto'),
        strategy=config['training'].get('strategy', 'auto'),
        callbacks=callbacks,
        logger=pl.loggers.WandbLogger() if wandb.run else True,
        enable_progress_bar=config['training'].get('progress_bar', True)
    )

    # Train model
    trainer.fit(model, data_module, ckpt_path=args.checkpoint)

    # Save final model
    trainer.save_checkpoint(
        f"{config['training']['checkpoint_dir']}/final_model.ckpt"
    )

    # Export model for inference
    export_model_for_inference(model, config)

    logger.info("Training completed successfully!")


def export_model_for_inference(model, config):
    """Export trained model for C++ inference."""
    # Create export directory
    export_dir = Path(config['export']['output_dir'])
    export_dir.mkdir(exist_ok=True)

    # Export model weights
    model_weights = {
        'rff_weights': model.rff.omega.detach().cpu().numpy(),
        'rff_bias': model.rff.bias.detach().cpu().numpy(),
        'parameter_predictor': {
            'weights': [layer.weight.detach().cpu().numpy()
                       for layer in model.parameter_predictor
                       if hasattr(layer, 'weight')],
            'biases': [layer.bias.detach().cpu().numpy()
                      for layer in model.parameter_predictor
                      if hasattr(layer, 'bias')]
        }
    }

    # Save as numpy arrays for C++ loading
    np.savez(export_dir / 'qihse_model_weights.npz', **model_weights)

    # Save configuration
    with open(export_dir / 'model_config.json', 'w') as f:
        json.dump(config['model'], f, indent=2)

    logger.info(f"Model exported to {export_dir}")


if __name__ == '__main__':
    main()
