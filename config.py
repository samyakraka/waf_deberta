"""
Configuration file for WAF Pipeline
Customize training parameters here
"""

from src.trainer import TrainingConfig


# ============================================================================
# TRAINING CONFIGURATIONS
# ============================================================================

# Default configuration (balanced for M4 MacBook Air)
DEFAULT_CONFIG = TrainingConfig(
    model_name="microsoft/deberta-v3-small",
    max_length=256,
    batch_size=16,
    learning_rate=2e-5,
    num_epochs=5,
    warmup_steps=500,
    weight_decay=0.01,
    mlm_probability=0.15,
    gradient_accumulation_steps=2,
    max_grad_norm=1.0,
    save_steps=1000,
    eval_steps=500,
    logging_steps=100,
    output_dir="models/deberta-waf",
    use_mps=True,
    seed=42
)


# Fast training (for testing, lower accuracy)
FAST_CONFIG = TrainingConfig(
    model_name="microsoft/deberta-v3-small",
    max_length=128,
    batch_size=32,
    learning_rate=3e-5,
    num_epochs=3,
    warmup_steps=200,
    gradient_accumulation_steps=1,
    output_dir="models/deberta-waf-fast",
    use_mps=True
)


# High accuracy (longer training time)
ACCURACY_CONFIG = TrainingConfig(
    model_name="microsoft/deberta-v3-small",
    max_length=256,  # Reduced from 512 to avoid memory issues
    batch_size=8,
    learning_rate=1e-5,
    num_epochs=10,
    warmup_steps=1000,
    weight_decay=0.02,
    gradient_accumulation_steps=4,
    output_dir="models/deberta-waf-accurate",
    use_mps=True
)


# CPU-only configuration (no MPS)
CPU_CONFIG = TrainingConfig(
    model_name="microsoft/deberta-v3-small",
    max_length=256,
    batch_size=8,
    learning_rate=2e-5,
    num_epochs=5,
    gradient_accumulation_steps=4,
    output_dir="models/deberta-waf-cpu",
    use_mps=False
)


# ============================================================================
# DATASET CONFIGURATIONS
# ============================================================================

DATASET_CONFIG = {
    'train_split': 0.8,          # 80% training, 20% validation
    'dataset_name': 'waf_dataset',
    'max_samples': None,          # None = use all data
    'shuffle': True,
    'random_seed': 42
}


# ============================================================================
# PARSING CONFIGURATIONS
# ============================================================================

PARSING_CONFIG = {
    'normalize_uuids': True,
    'normalize_ids': True,
    'normalize_tokens': True,
    'normalize_emails': True,
    'max_body_length': 100,
    'max_param_value_length': 50,
    'preserve_structure': True
}


# ============================================================================
# REDIS CONFIGURATIONS
# ============================================================================

REDIS_CONFIG = {
    'host': 'localhost',
    'port': 6379,
    'db': 0,
    'password': None,  # Set if Redis requires authentication
    'decode_responses': True,
    'socket_timeout': 5,
    'socket_connect_timeout': 5
}


# ============================================================================
# DIRECTORY CONFIGURATIONS
# ============================================================================

DIR_CONFIG = {
    'logs_dir': 'logs',
    'output_dir': 'output',
    'parsed_dir': 'output/parsed',
    'tokenized_dir': 'output/tokenized',
    'models_dir': 'models',
    'cache_dir': '.cache'
}


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

"""
To use a specific configuration in your code:

1. In pipeline.py:
   from config import ACCURACY_CONFIG
   pipeline.run_full_pipeline(training_config=ACCURACY_CONFIG)

2. In training script:
   from config import FAST_CONFIG
   trainer = WAFTrainer(FAST_CONFIG)

3. Custom configuration:
   from config import DEFAULT_CONFIG
   custom_config = DEFAULT_CONFIG
   custom_config.batch_size = 32
   custom_config.num_epochs = 10
"""
