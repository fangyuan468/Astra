pub use astra_turn_core::turn_trace_collector::*;

#[cfg(test)]
mod tests {
    use crate::observability::{ObservabilityHub, on_context_assembled};
    use astra_turn_core::turn_trace_collector::TurnTraceCollector;

    #[test]
    fn shared_hub_preserves_history_availability_per_session_and_request() {
        use crate::observability::latest_context_trace_signal;
        use astra_turn_core::context_assembly_trace::TurnRetention;
        let hub = ObservabilityHub::new();
        let a = hub.start_session("owner", "session-a");
        let b = hub.start_session("owner", "session-b");
        let first = TurnTraceCollector::new("turn-1", "session-a");
        first.clone_arc().set_history_retained(&[TurnRetention {
            turn_index: 0,
            role: "user".into(),
            tokens: 30,
            has_tool_calls: false,
            content_preview: "a-only".into(),
        }]);
        on_context_assembled(&mut a.write().unwrap(), first.finalize());
        let other = TurnTraceCollector::new("turn-1", "session-b");
        on_context_assembled(&mut b.write().unwrap(), other.finalize());
        assert!(
            latest_context_trace_signal(&b.read().unwrap())
                .unwrap()
                .history
                .is_none()
        );
        let signal = latest_context_trace_signal(&a.read().unwrap()).unwrap();
        assert_eq!(signal.history.unwrap().total_tokens, 30);
        first.set_history_retained(&[]);
        on_context_assembled(&mut a.write().unwrap(), first.finalize());
        let empty = latest_context_trace_signal(&a.read().unwrap())
            .unwrap()
            .history
            .unwrap();
        assert_eq!(empty.retained_groups, 0);
        assert_eq!(empty.total_tokens, 0);
        let next = TurnTraceCollector::new("turn-2", "session-a");
        on_context_assembled(&mut a.write().unwrap(), next.finalize());
        assert!(
            latest_context_trace_signal(&a.read().unwrap())
                .unwrap()
                .history
                .is_none()
        );
        assert!(
            latest_context_trace_signal(&b.read().unwrap())
                .unwrap()
                .history
                .is_none()
        );
    }

    #[test]
    fn finalize_feeds_observability_session() {
        let collector = TurnTraceCollector::new("turn-0", "sess-1");
        collector
            .record_token_budget_estimate(14_000, 5_000, 500, 3_000, 200, 22_700, 128_000, 0.18);
        collector.record_tool_surface(
            &["bash".into(), "view".into()],
            &[("bash".into(), 1500), ("view".into(), 1500)],
            40,
            12,
        );
        collector.record_memory_retrieval(
            "rust error handling",
            5,
            &[("use thiserror".into(), 0.9)],
            25,
        );

        let trace = collector.finalize();
        assert_eq!(trace.token_budget.system_prompt_tokens, 14_000);
        assert_eq!(trace.token_budget.history_tokens, 5_000);
        assert_eq!(trace.tools.visible_tools.len(), 2);
        assert_eq!(trace.memory.memories_selected.len(), 1);

        // Feed to observability session
        let hub = ObservabilityHub::new();
        let session = hub.start_session("u1", "sess-1");
        {
            let mut guard = session.write().unwrap();
            on_context_assembled(&mut guard, trace);
        }
        let guard = session.read().unwrap();
        assert_eq!(guard.context_traces.len(), 1);
        let t = &guard.context_traces[0];
        assert_eq!(t.turn_id, "turn-0");
        assert_eq!(t.token_budget.system_prompt_tokens, 14_000);
        assert_eq!(t.tools.visible_tools.len(), 2);
        assert_eq!(t.memory.retrieval_latency_ms, 25);
    }
}
