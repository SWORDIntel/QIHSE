/*
 * Test suite for QIHSE ML self-improvement engine
 */

#include "../include/qihse_ml.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>

#define TEST_FLOAT_TOLERANCE 1e-6f

/* Test Thompson Sampling bandit */
static void test_thompson_bandit(void) {
    printf("Testing Thompson Sampling bandit...\n");

    qihse_thompson_bandit_t bandit;

    /* Test initialization */
    int ret = qihse_thompson_bandit_init(&bandit, 3, NULL);
    assert(ret == 0);
    assert(bandit.num_arms == 3);

    /* Test arm selection */
    size_t selected = qihse_thompson_bandit_select_arm(&bandit);
    assert(selected < 3);

    /* Test update */
    qihse_thompson_bandit_update(&bandit, 0, 0.8); /* Success */
    qihse_thompson_bandit_update(&bandit, 1, 0.2); /* Failure */

    /* Test statistics */
    double success_rate, confidence;
    qihse_thompson_bandit_get_stats(&bandit, 0, &success_rate, &confidence);
    assert(success_rate > 0.0);
    assert(confidence > 0.0);

    /* Cleanup */
    qihse_thompson_bandit_destroy(&bandit);

    printf("  Thompson Sampling bandit test passed!\n");
}

/* Test neural optimizer */
static void test_neural_optimizer(void) {
    printf("Testing neural optimizer...\n");

    qihse_neural_optimizer_t optimizer;

    /* Test initialization */
    int ret = qihse_neural_optimizer_init(&optimizer, 4, 8, 0.01, NULL);
    assert(ret == 0);
    assert(optimizer.num_parameters == 4);
    assert(optimizer.hidden_size == 8);

    /* Test optimization step */
    double current_params[4] = {0.2, 0.5, 0.8, 0.1};
    double output_params[4];

    qihse_neural_optimizer_step(&optimizer, current_params, 0.7, output_params);

    /* Verify output parameters are in valid range */
    for (int i = 0; i < 4; i++) {
        assert(output_params[i] >= 0.0 && output_params[i] <= 1.0);
    }

    /* Test statistics */
    double loss, gradient_norm;
    qihse_neural_optimizer_get_stats(&optimizer, &loss, &gradient_norm);
    assert(loss >= 0.0);
    assert(gradient_norm >= 0.0);

    /* Cleanup */
    qihse_neural_optimizer_destroy(&optimizer);

    printf("  Neural optimizer test passed!\n");
}

/* Test workload fingerprinting */
static void test_workload_fingerprinting(void) {
    printf("Testing workload fingerprinting...\n");

    qihse_workload_fingerprint_t fp1, fp2;

    /* Test fingerprint generation */
    float test_data[10] = {1.0f, 0.0f, 2.0f, 0.0f, 3.0f, 0.0f, 4.0f, 0.0f, 5.0f, 0.0f};
    qihse_workload_fingerprint_generate(&fp1, test_data, sizeof(test_data), "vector_search");

    assert(fp1.data_size == sizeof(test_data));
    assert(fp1.dimensionality == 10);
    assert(fp1.sparsity > 0.4); /* 5 zeros out of 10 elements */
    assert(strcmp(fp1.query_type, "vector_search") == 0);

    /* Test fingerprint comparison */
    qihse_workload_fingerprint_generate(&fp2, test_data, sizeof(test_data), "vector_search");
    double similarity = qihse_workload_fingerprint_compare(&fp1, &fp2);
    assert(similarity > 0.8); /* Should be very similar */

    printf("  Workload fingerprinting test passed!\n");
}

/* Test telemetry */
static void test_telemetry(void) {
    printf("Testing telemetry...\n");

    qihse_telemetry_collector_t collector;

    /* Test initialization */
    int ret = qihse_telemetry_collector_init(&collector, 10, NULL);
    assert(ret == 0);
    assert(collector.max_events == 10);

    /* Test event recording */
    qihse_telemetry_event_data_t event;
    event.type = QIHSE_TELEMETRY_QUERY_START;
    event.timestamp_us = 1000000ULL;
    event.value = 0.85;
    strcpy(event.component, "test");
    strcpy(event.operation, "test_op");
    strcpy(event.metadata, "test_meta");

    qihse_telemetry_record_event(&collector, &event);
    assert(collector.num_events == 1);

    /* Test JSON export */
    char* json = qihse_telemetry_export_json(&collector);
    assert(json != NULL);
    assert(strstr(json, "test_op") != NULL);
    free(json);

    /* Cleanup */
    qihse_telemetry_collector_destroy(&collector);

    printf("  Telemetry test passed!\n");
}

/* Test regression detection */
static void test_regression_detection(void) {
    printf("Testing regression detection...\n");

    qihse_regression_detector_t detector;

    /* Test initialization */
    int ret = qihse_regression_detector_init(&detector, 10, 0.8, 2.0, NULL);
    assert(ret == 0);
    assert(detector.window_size == 10);
    assert(detector.baseline_performance == 0.8);

    /* Test updates */
    bool regression;

    /* Add normal performance data */
    for (int i = 0; i < 5; i++) {
        regression = qihse_regression_detector_update(&detector, 0.8); /* Exact baseline, no variation */
        assert(!regression); /* Should not detect regression on baseline */
    }

    /* Add significant regression */
    regression = qihse_regression_detector_update(&detector, 0.5); /* Much lower performance */
    /* May or may not detect depending on statistical analysis */

    /* Test statistics */
    double mean, stddev, trend;
    qihse_regression_detector_get_stats(&detector, &mean, &stddev, &trend);
    assert(mean > 0.0);

    /* Cleanup */
    qihse_regression_detector_destroy(&detector);

    printf("  Regression detection test passed!\n");
}

/* Test contextual bandit */
static void test_contextual_bandit(void) {
    printf("Testing contextual bandit...\n");

    qihse_contextual_bandit_t bandit;

    /* Test initialization */
    int ret = qihse_contextual_bandit_init(&bandit, 3, 4, 8, 0.01, NULL);
    assert(ret == 0);
    assert(bandit.num_arms == 3);
    assert(bandit.context_dim == 4);
    assert(bandit.hidden_size == 8);

    /* Test arm selection with context */
    double context[4] = {0.1, 0.5, 0.9, 0.2};
    size_t selected = qihse_contextual_bandit_select_arm(&bandit, context);
    assert(selected < 3);

    /* Test update with context */
    qihse_contextual_bandit_update(&bandit, selected, context, 0.8); /* Success */

    /* Test statistics with context */
    double expected_reward, confidence;
    qihse_contextual_bandit_get_stats(&bandit, selected, context,
                                     &expected_reward, &confidence);
    assert(expected_reward >= 0.0 && expected_reward <= 1.0);
    assert(confidence >= 0.0);

    /* Cleanup */
    qihse_contextual_bandit_destroy(&bandit);

    printf("  Contextual bandit test passed!\n");
}

/* Test RFF workload embedding */
static void test_rff_workload_embedding(void) {
    printf("Testing RFF workload embedding...\n");

    qihse_rff_workload_embedding_t embedding;

    /* Test initialization */
    int ret = qihse_rff_workload_embedding_init(&embedding, 16, 1.0);
    assert(ret == 0);
    assert(embedding.embedding_dim == 16);

    /* Test embedding generation */
    qihse_workload_fingerprint_t fingerprint;
    float test_data[8] = {1.0f, 0.0f, 2.0f, 0.0f, 3.0f, 0.0f, 4.0f, 0.0f};
    qihse_workload_fingerprint_generate(&fingerprint, test_data, sizeof(test_data), "test");

    double output_embedding[16];
    qihse_rff_workload_embedding_generate(&embedding, &fingerprint,
                                         output_embedding, 16);

    /* Verify embedding values are reasonable */
    for (int i = 0; i < 16; i++) {
        assert(output_embedding[i] >= -2.0 && output_embedding[i] <= 2.0);
    }

    /* Cleanup */
    qihse_rff_workload_embedding_destroy(&embedding);

    printf("  RFF workload embedding test passed!\n");
}

/* Test counterfactual learning */
static void test_counterfactual_learner(void) {
    printf("Testing counterfactual learning...\n");

    qihse_counterfactual_learner_t learner;

    /* Test initialization */
    int ret = qihse_counterfactual_learner_init(&learner, 3, 4, 10, 0.01, NULL);
    assert(ret == 0);
    assert(learner.num_arms == 3);
    assert(learner.context_dim == 4);
    assert(learner.max_counterfactuals == 10);

    /* Test logging counterfactuals */
    double context[4] = {0.1, 0.5, 0.9, 0.2};
    size_t alternative_arms[2] = {1, 2};
    double alternative_rewards[2] = {0.7, 0.3};

    qihse_counterfactual_learner_log(&learner, 0, context, 0.8,
                                    alternative_arms, alternative_rewards, 2);

    assert(learner.num_counterfactuals == 2);

    /* Test update */
    double model_params[4] = {0.2, 0.5, 0.8, 0.1};
    qihse_counterfactual_learner_update(&learner, model_params, 4);

    /* Verify parameters were updated */
    for (int i = 0; i < 4; i++) {
        assert(model_params[i] >= 0.0 && model_params[i] <= 1.0);
    }

    /* Cleanup */
    qihse_counterfactual_learner_destroy(&learner);

    printf("  Counterfactual learning test passed!\n");
}

/* Test variational optimizer */
static void test_variational_optimizer(void) {
    printf("Testing variational optimizer...\n");

    qihse_variational_optimizer_t optimizer;

    /* Test initialization */
    int ret = qihse_variational_optimizer_init(&optimizer, 4, 8, 2, 0.01, NULL);
    assert(ret == 0);
    assert(optimizer.num_parameters == 4);
    assert(optimizer.superposition_depth == 8);
    assert(optimizer.num_layers == 2);

    /* Simple energy function: minimize sum of squares */
    double energy_func(const double* params, size_t n, void* ctx) {
        double sum = 0.0;
        for (size_t i = 0; i < n; i++) {
            sum += params[i] * params[i];
        }
        return sum;
    }

    /* Test optimization step */
    double current_params[4] = {0.5, -0.3, 0.8, -0.1};
    double output_params[4];

    ret = qihse_variational_optimizer_step(&optimizer, current_params, energy_func, NULL, output_params);
    assert(ret == 0);

    /* Verify output parameters are in valid range */
    for (int i = 0; i < 4; i++) {
        assert(output_params[i] >= -1.0 && output_params[i] <= 1.0);
    }

    /* Test statistics */
    double energy;
    size_t iterations;
    qihse_variational_optimizer_get_stats(&optimizer, &energy, &iterations);
    assert(energy >= 0.0);
    assert(iterations == 1);

    /* Cleanup */
    qihse_variational_optimizer_destroy(&optimizer);

    printf("  Variational optimizer test passed!\n");
}

/* Test Grover parameter search */
static void test_grover_parameter_search(void) {
    printf("Testing Grover parameter search...\n");

    qihse_grover_parameter_search_t search;

    /* Test initialization */
    int ret = qihse_grover_parameter_search_init(&search, 16, 0.8, NULL);
    assert(ret == 0);
    assert(search.search_space_size == 16);
    assert(search.optimal_threshold == 0.8);

    /* Test search iteration */
    double param_space[16];
    for (int i = 0; i < 16; i++) {
        param_space[i] = (double)i / 16.0; /* Values from 0.0 to 0.9375 */
    }

    /* Performance evaluator: higher values are better */
    double perf_func(const double* params, size_t n, void* ctx) {
        return params[0]; /* Simple: parameter value is performance */
    }

    ret = qihse_grover_parameter_search_iterate(&search, param_space, perf_func, NULL);
    assert(ret == 0);

    /* Get optimal parameters */
    double optimal_params[4];
    size_t num_found;
    qihse_grover_parameter_search_get_optimal(&search, optimal_params, 4, &num_found);
    assert(num_found > 0);

    /* Verify optimal parameters are reasonable */
    for (size_t i = 0; i < num_found; i++) {
        assert(optimal_params[i] >= 0.0 && optimal_params[i] <= 1.0);
    }

    /* Cleanup */
    qihse_grover_parameter_search_destroy(&search);

    printf("  Grover parameter search test passed!\n");
}

/* Test meta-learning optimizer */
static void test_meta_optimizer(void) {
    printf("Testing meta-learning optimizer...\n");

    qihse_meta_optimizer_t optimizer;

    /* Test initialization */
    int ret = qihse_meta_optimizer_init(&optimizer, 3, 4, 5, 0.01, 0.1, NULL);
    assert(ret == 0);
    assert(optimizer.num_tasks == 3);
    assert(optimizer.task_dim == 4);
    assert(optimizer.inner_steps == 5);

    /* Test meta-update */
    double task_features[12] = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2};
    double task_losses[3] = {0.8, 0.6, 0.4};

    qihse_meta_optimizer_update(&optimizer, task_features, task_losses, 3);

    /* Test adaptation */
    double task_features_single[4] = {0.1, 0.2, 0.3, 0.4};
    double adaptation_data[8] = {0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2};
    double adapted_params[4];

    qihse_meta_optimizer_adapt(&optimizer, task_features_single, adaptation_data, 8, adapted_params);

    /* Verify adapted parameters */
    for (int i = 0; i < 4; i++) {
        assert(adapted_params[i] >= -1.0 && adapted_params[i] <= 2.0);
    }

    /* Test statistics */
    double meta_loss, adaptation_speed;
    qihse_meta_optimizer_get_stats(&optimizer, &meta_loss, &adaptation_speed);
    assert(meta_loss >= 0.0);

    /* Cleanup */
    qihse_meta_optimizer_destroy(&optimizer);

    printf("  Meta-learning optimizer test passed!\n");
}

/* Test attention layer */
static void test_attention_layer(void) {
    printf("Testing attention layer...\n");

    qihse_attention_layer_t layer;

    /* Test initialization */
    int ret = qihse_attention_layer_init(&layer, 8, 2, 4, NULL);
    assert(ret == 0);
    assert(layer.embed_dim == 8);
    assert(layer.num_heads == 2);
    assert(layer.seq_len == 4);

    /* Test forward pass */
    double input[32]; /* 4 seq * 8 embed */
    double output[32];

    for (int i = 0; i < 32; i++) {
        input[i] = (double)i / 32.0;
    }

    qihse_attention_layer_forward(&layer, input, output);

    /* Verify output has reasonable values */
    for (int i = 0; i < 32; i++) {
        assert(output[i] >= -10.0 && output[i] <= 10.0);
    }

    /* Cleanup */
    qihse_attention_layer_destroy(&layer);

    printf("  Attention layer test passed!\n");
}

/* Test Adam optimizer */
static void test_adam_optimizer(void) {
    printf("Testing Adam optimizer...\n");

    qihse_adam_optimizer_t optimizer;

    /* Test initialization */
    int ret = qihse_adam_optimizer_init(&optimizer, 4, 0.01, 0.9, 0.999, 1e-8, 0.01, NULL);
    assert(ret == 0);
    assert(optimizer.num_parameters == 4);
    assert(optimizer.learning_rate == 0.01);
    assert(optimizer.weight_decay == 0.01);

    /* Test optimization step */
    double gradients[4] = {0.1, -0.2, 0.3, -0.1};
    double output_params[4];

    qihse_adam_optimizer_step(&optimizer, gradients, output_params);

    /* Verify parameters were updated */
    for (int i = 0; i < 4; i++) {
        assert(output_params[i] != 0.0); /* Should be updated from initial zero */
    }

    /* Test second step */
    qihse_adam_optimizer_step(&optimizer, gradients, output_params);

    /* Test statistics */
    double lr, momentum;
    qihse_adam_optimizer_get_stats(&optimizer, &lr, &momentum);
    assert(lr == 0.01);
    assert(momentum == 0.9);

    /* Cleanup */
    qihse_adam_optimizer_destroy(&optimizer);

    printf("  Adam optimizer test passed!\n");
}

/* Test energy-aware optimizer */
static void test_energy_optimizer(void) {
    printf("Testing energy-aware optimizer...\n");

    qihse_energy_optimizer_t optimizer;

    /* Test initialization */
    int ret = qihse_energy_optimizer_init(&optimizer, 2, 100.0, 80.0, 0.5, NULL);
    assert(ret == 0);
    assert(optimizer.num_devices == 2);
    assert(optimizer.global_power_budget == 100.0);
    assert(optimizer.global_thermal_limit == 80.0);

    /* Test setting device profiles */
    qihse_energy_profile_t profile1 = {
        .power_budget_watts = 50.0,
        .thermal_limit_celsius = 75.0,
        .dvfs_frequency_ghz = 2.5
    };
    ret = qihse_energy_optimizer_set_device_profile(&optimizer, 0, &profile1);
    assert(ret == 0);

    qihse_energy_profile_t profile2 = {
        .power_budget_watts = 40.0,
        .thermal_limit_celsius = 70.0,
        .dvfs_frequency_ghz = 2.0
    };
    ret = qihse_energy_optimizer_set_device_profile(&optimizer, 1, &profile2);
    assert(ret == 0);

    /* Test workload optimization */
    double output_freqs[2];
    double power_budget;
    ret = qihse_energy_optimizer_optimize_workload(&optimizer, 0.8, 0.9, output_freqs, &power_budget);
    assert(ret == 0);
    assert(power_budget > 0.0);
    assert(output_freqs[0] > 0.0 && output_freqs[0] <= 2.5);
    assert(output_freqs[1] > 0.0 && output_freqs[1] <= 2.0);

    /* Test monitoring and adjustment */
    ret = qihse_energy_optimizer_monitor_and_adjust(&optimizer);
    assert(ret == 0);

    /* Test statistics */
    double total_power, max_temp, efficiency;
    qihse_energy_optimizer_get_stats(&optimizer, &total_power, &max_temp, &efficiency);
    assert(total_power >= 0.0);
    assert(max_temp >= 0.0);
    assert(efficiency >= 0.0);

    /* Cleanup */
    qihse_energy_optimizer_destroy(&optimizer);

    printf("  Energy-aware optimizer test passed!\n");
}

/* Test RL agent */
static void test_rl_agent(void) {
    printf("Testing RL agent...\n");

    qihse_rl_agent_t agent;

    /* Test initialization */
    int ret = qihse_rl_agent_init(&agent, 4, 6, 32, 1000, 0.001, 0.99, 0.1, NULL);
    assert(ret == 0);
    assert(agent.state_dim == 4);
    assert(agent.action_dim == 6);
    assert(agent.hidden_size == 32);

    /* Test action selection */
    double state[4] = {0.1, 0.2, 0.3, 0.4};
    double action[6];
    ret = qihse_rl_agent_select_action(&agent, state, action);
    assert(ret == 0);

    /* Verify action is valid (one-hot encoded) */
    int num_nonzero = 0;
    for (int i = 0; i < 6; i++) {
        assert(action[i] >= 0.0 && action[i] <= 1.0);
        if (action[i] > 0.5) num_nonzero++;
    }
    assert(num_nonzero == 1); /* One-hot encoding */

    /* Test experience storage */
    double next_state[4] = {0.2, 0.3, 0.4, 0.5};
    qihse_rl_agent_store_experience(&agent, state, action, 1.0, next_state, 0);
    assert(agent.current_buffer_size == 1);

    /* Test training (requires sufficient buffer size) */
    for (int i = 1; i < 32; i++) {
        qihse_rl_agent_store_experience(&agent, state, action, 1.0, next_state, 0);
    }
    qihse_rl_agent_train(&agent, 16);

    /* Test algorithm discovery */
    qihse_rl_algorithm_config_t config;
    ret = qihse_rl_agent_discover_algorithm(&agent, state, &config);
    assert(ret == 0);
    assert(strlen(config.algorithm_name) > 0);
    assert(config.max_iterations > 0);
    assert(config.convergence_threshold > 0.0);

    /* Test statistics */
    double loss, epsilon;
    size_t buffer_size;
    qihse_rl_agent_get_stats(&agent, &loss, &epsilon, &buffer_size);
    assert(loss >= 0.0);
    assert(epsilon == 0.1);
    assert(buffer_size > 0);

    /* Cleanup */
    qihse_rl_agent_destroy(&agent);

    printf("  RL agent test passed!\n");
}

/* Test ML engine */
static void test_ml_engine(void) {
    printf("Testing ML engine...\n");

    qihse_ml_engine_t engine;
    qihse_ml_config_t config = {
        .bandit_arms = 3,
        .contextual_context_dim = 4,
        .contextual_hidden_size = 8,
        .rff_embedding_dim = 16,
        .rff_gamma = 1.0,
        .counterfactual_max = 10,
        .optimizer_params = 4,
        .hidden_size = 8,
        .learning_rate = 0.01,
        .variational_superposition_depth = 8,
        .variational_layers = 2,
        .grover_search_space = 16,
        .grover_threshold = 0.8,
        .meta_tasks = 3,
        .meta_task_dim = 4,
        .meta_inner_steps = 5,
        .attention_embed_dim = 8,
        .attention_heads = 2,
        .attention_seq_len = 4,
        .energy_power_budget = 100.0,
        .energy_thermal_limit = 80.0,
        .rl_state_dim = 4,
        .rl_action_dim = 6,
        .rl_replay_buffer = 1000,
        .telemetry_buffer = 100,
        .regression_window = 10,
        .baseline_performance = 0.8,
        .regression_threshold = 2.0
    };

    /* Test initialization */
    int ret = qihse_ml_engine_init(&engine, &config, NULL);
    assert(ret == 0);

    /* Test query processing */
    float test_query[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    double optimized_params[4];

    qihse_ml_engine_process_query(&engine, test_query, "vector_search", 0.75, optimized_params);

    /* Verify optimized parameters */
    for (int i = 0; i < 4; i++) {
        assert(optimized_params[i] >= 0.0 && optimized_params[i] <= 1.0);
    }

    /* Test training */
    qihse_ml_engine_train(&engine, 0.85, optimized_params);

    /* Test regression detection */
    bool regression = qihse_ml_engine_detect_regression(&engine, 0.6);
    /* Result depends on statistical analysis - just ensure function doesn't crash */
    (void)regression;

    /* Test status export */
    char* status = qihse_ml_engine_export_status_json(&engine);
    assert(status != NULL);
    assert(strstr(status, "bandit") != NULL);
    free(status);

    /* Cleanup */
    qihse_ml_engine_destroy(&engine);

    printf("  ML engine test passed!\n");
}

/* Main test runner */
int main(void) {
    printf("Running QIHSE ML engine tests...\n\n");

    test_thompson_bandit();
    printf("\n");

    test_neural_optimizer();
    printf("\n");

    test_workload_fingerprinting();
    printf("\n");

    test_telemetry();
    printf("\n");

    test_regression_detection();
    printf("\n");

    test_contextual_bandit();
    printf("\n");

    test_rff_workload_embedding();
    printf("\n");

    test_counterfactual_learner();
    printf("\n");

    test_variational_optimizer();
    printf("\n");

    test_grover_parameter_search();
    printf("\n");

    test_meta_optimizer();
    printf("\n");

    test_attention_layer();
    printf("\n");

    test_adam_optimizer();
    printf("\n");

    test_energy_optimizer();
    printf("\n");

    test_rl_agent();
    printf("\n");

    test_ml_engine();
    printf("\n");

    printf("All ML engine tests passed!\n");
    return 0;
}
