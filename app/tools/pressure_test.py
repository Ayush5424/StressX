import asyncio
import time
from typing import Any, Optional
import httpx

from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.attempt import AttackAttempt


class PressureTestTool(BaseTool):
    """Tool for conducting controlled, bounded, adaptive pressure and rate-limit experimentation."""

    name = "pressure_test"
    description = (
        "Applies controlled adaptive pressure (LOW -> MEDIUM -> HIGH -> BACK OFF -> RECOVERY) to test "
        "rate limiting, threshold behavior, degradation, and system resilience within strict sandbox limits. "
        "Records baseline, status distribution, degradation threshold, and recovery."
    )
    parameters_schema = {
        "type": "object",
        "required": ["path"],
        "properties": {
            "path": {"type": "string", "description": "Target endpoint path to pressure test"},
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"], "default": "GET"},
            "headers": {"type": "object", "description": "HTTP request headers"},
            "params": {"type": "object", "description": "Query parameters"},
            "body": {"type": "string", "description": "Request body string"},
            "initial_rate": {"type": "integer", "default": 5, "description": "Starting request rate (req/s)"},
            "max_rate": {"type": "integer", "default": 20, "description": "Maximum target rate (max 30 req/s)"},
            "concurrency": {"type": "integer", "default": 2, "description": "Worker concurrency (max 10)"},
            "max_total_requests": {"type": "integer", "default": 30, "description": "Total bounded requests across all stages (max 50)"}
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        path = kwargs.get("path", "/")
        method = kwargs.get("method", "GET").upper()
        headers = kwargs.get("headers", {}) or {}
        params = kwargs.get("params") or None
        body = kwargs.get("body")

        # Hard sandbox boundary protections
        initial_rate = max(1, min(int(kwargs.get("initial_rate", 5)), 10))
        max_rate = max(initial_rate, min(int(kwargs.get("max_rate", 20)), 30))
        concurrency = max(1, min(int(kwargs.get("concurrency", 2)), 10))
        max_total_requests = max(10, min(int(kwargs.get("max_total_requests", 30)), 50))

        resolved_url = self.validate_target(session, path)

        if "Authorization" not in headers and "active_token" in session.context_data:
            headers["Authorization"] = f"Bearer {session.context_data['active_token']}"

        insights: list[str] = []
        status_dist: dict[str, int] = {}
        all_latencies: list[float] = []
        samples_collected: list[dict[str, Any]] = []

        total_requests_sent = 0

        async def _dispatch_single(client: httpx.AsyncClient) -> tuple[int, float, str]:
            t0 = time.perf_counter()
            try:
                res = await client.request(
                    method=method,
                    url=resolved_url,
                    headers=headers,
                    params=params,
                    content=body.encode("utf-8") if isinstance(body, str) else None
                )
                el = (time.perf_counter() - t0) * 1000.0
                return res.status_code, round(el, 2), res.text[:200]
            except Exception as ex:
                el = (time.perf_counter() - t0) * 1000.0
                return 0, round(el, 2), f"Error: {type(ex).__name__}"

        # 1. ESTABLISH BASELINE (Stage 1: 3 requests at 2 req/s)
        baseline_latencies: list[float] = []
        baseline_statuses: list[int] = []

        async with httpx.AsyncClient(timeout=6.0, follow_redirects=False) as client:
            for _ in range(3):
                sc, el, txt = await _dispatch_single(client)
                total_requests_sent += 1
                baseline_latencies.append(el)
                baseline_statuses.append(sc)
                status_dist[str(sc)] = status_dist.get(str(sc), 0) + 1
                all_latencies.append(el)
                await asyncio.sleep(0.3)

            base_mean = round(sum(baseline_latencies) / len(baseline_latencies), 2) if baseline_latencies else 0.0
            base_healthy = all(200 <= s < 400 for s in baseline_statuses)

            # 2. ADAPTIVE PRESSURE ESCALATION (Stages: Low -> Med -> High)
            stages = [
                {"name": "LOW", "rate": initial_rate, "count": min(8, max_total_requests - total_requests_sent)},
                {"name": "MEDIUM", "rate": min(initial_rate * 2, max_rate), "count": min(12, max(0, max_total_requests - total_requests_sent))},
                {"name": "HIGH", "rate": max_rate, "count": min(15, max(0, max_total_requests - total_requests_sent))}
            ]

            threshold_identified = False
            threshold_rate = 0
            threshold_reason = ""
            degradation_detected = False
            rate_limit_detected = False
            retry_after_header: Optional[str] = None
            stage_results: list[dict[str, Any]] = []

            for stage in stages:
                count = stage["count"]
                if count <= 0 or threshold_identified:
                    break

                target_rate = stage["rate"]
                delay = 1.0 / target_rate if target_rate > 0 else 0.1

                stage_lats: list[float] = []
                stage_stats: list[int] = []

                # Dispatch bounded requests in small batches matching concurrency
                for i in range(0, count, concurrency):
                    batch_size = min(concurrency, count - i)
                    tasks = [_dispatch_single(client) for _ in range(batch_size)]
                    results = await asyncio.gather(*tasks)

                    for sc, el, txt in results:
                        total_requests_sent += 1
                        stage_lats.append(el)
                        stage_stats.append(sc)
                        all_latencies.append(el)
                        s_str = str(sc)
                        status_dist[s_str] = status_dist.get(s_str, 0) + 1
                        if len(samples_collected) < 6:
                            samples_collected.append({"status": sc, "latency_ms": el, "snippet": txt})

                        if sc == 429:
                            rate_limit_detected = True

                    await asyncio.sleep(delay)

                stage_mean = round(sum(stage_lats) / len(stage_lats), 2) if stage_lats else 0.0
                err_count = sum(1 for s in stage_stats if s >= 500 or s == 0)
                err_rate = round(err_count / len(stage_stats), 2) if stage_stats else 0.0

                stage_record = {
                    "stage": stage["name"],
                    "target_rate": target_rate,
                    "mean_latency_ms": stage_mean,
                    "error_rate": err_rate,
                    "status_breakdown": {str(k): stage_stats.count(k) for k in set(stage_stats)}
                }
                stage_results.append(stage_record)

                # Check for rate limiting
                if rate_limit_detected and not threshold_identified:
                    threshold_identified = True
                    threshold_rate = target_rate
                    threshold_reason = f"HTTP 429 Too Many Requests detected at ~{target_rate} req/s"
                    insights.append(f"Rate limiting active: HTTP 429 throttled incoming traffic at ~{target_rate} req/s.")
                    break

                # Check for latency or error degradation
                if base_mean > 0 and stage_mean > max(base_mean * 3.5, 400.0):
                    degradation_detected = True
                    if not threshold_identified:
                        threshold_identified = True
                        threshold_rate = target_rate
                        threshold_reason = f"Latency degradation: mean jumped to {stage_mean}ms (baseline: {base_mean}ms) at {target_rate} req/s"
                        insights.append(f"Degradation threshold: Latency escalated to {stage_mean}ms at {target_rate} req/s.")
                        break

                if err_rate >= 0.15:
                    degradation_detected = True
                    if not threshold_identified:
                        threshold_identified = True
                        threshold_rate = target_rate
                        threshold_reason = f"Error rate spiked to {err_rate*100:.0f}% (HTTP 5xx/connection drops) at {target_rate} req/s"
                        insights.append(f"Degradation threshold: Error rate reached {err_rate*100:.0f}% under {target_rate} req/s.")
                        break

            # 3. BACK OFF AND RECOVERY VERIFICATION (Stage: Recovery after 400ms cooldown)
            await asyncio.sleep(0.4)
            recovery_latencies: list[float] = []
            recovery_statuses: list[int] = []

            for _ in range(3):
                sc, el, txt = await _dispatch_single(client)
                total_requests_sent += 1
                recovery_latencies.append(el)
                recovery_statuses.append(sc)
                all_latencies.append(el)
                s_str = str(sc)
                status_dist[s_str] = status_dist.get(s_str, 0) + 1
                await asyncio.sleep(0.2)

            rec_mean = round(sum(recovery_latencies) / len(recovery_latencies), 2) if recovery_latencies else 0.0
            recovery_verified = all(200 <= s < 400 for s in recovery_statuses) and (rec_mean < max(base_mean * 2.0, 300.0))

            if recovery_verified:
                insights.append(f"Recovery verified: Post-stress latency normalized to {rec_mean}ms with healthy statuses.")
            else:
                insights.append(f"Recovery sluggish or incomplete: Post-stress latency {rec_mean}ms, statuses: {recovery_statuses}.")

        # 4. SYSTEM-DESIGN ANALYSIS (Distinguish OBSERVED from INFERRED)
        all_latencies.sort()
        mean_all_lat = round(sum(all_latencies) / len(all_latencies), 2) if all_latencies else 0.0
        p95_lat = all_latencies[int(0.95 * len(all_latencies))] if all_latencies else 0.0

        observed_facts = (
            f"OBSERVED: Baseline latency {base_mean}ms ({baseline_statuses[0] if baseline_statuses else 'N/A'}); "
            f"Total requests: {total_requests_sent}; Peak rate tested: {max_rate} req/s; "
            f"Status distribution: {status_dist}; Latency p95: {p95_lat}ms; "
            f"Degradation detected: {degradation_detected}; 429 detected: {rate_limit_detected}; "
            f"Recovery verified: {recovery_verified} (post-stress mean: {rec_mean}ms)."
        )

        if rate_limit_detected:
            inferred_conclusion = (
                f"INFERRED: Active rate limiting is enforced by the application/proxy at threshold ~{threshold_rate} req/s. "
                "Requests beyond this threshold receive HTTP 429 backpressure."
            )
        elif degradation_detected:
            inferred_conclusion = (
                f"INFERRED: Inadequate backpressure / rate limiting. Application degraded under moderate concurrency "
                f"({threshold_reason}). Worker or connection pool saturation suspected under sustained pressure."
            )
        else:
            inferred_conclusion = (
                f"INFERRED: Application handled sustained load up to {max_rate} req/s without measurable degradation "
                "or rate-limiting backpressure within authorized sandbox resource bounds."
            )

        summary = (
            f"Pressure experiment on {method} {path} complete ({total_requests_sent} requests, max {max_rate} req/s). "
            f"Status dist: {status_dist}. Degradation: {degradation_detected}, RateLimit: {rate_limit_detected}, Recovery: {recovery_verified}."
        )

        attempt = AttackAttempt(
            step=session.step_count,
            tool=self.name,
            target=resolved_url,
            action_summary=f"Controlled pressure experiment on {method} {path} (Peak {max_rate} req/s)",
            request_data={
                "method": method,
                "path": path,
                "initial_rate": initial_rate,
                "max_rate": max_rate,
                "concurrency": concurrency,
                "total_requests": total_requests_sent
            },
            response_summary=summary,
            result="RATE_LIMITING_OBSERVED" if rate_limit_detected else (
                "DEGRADATION_WITHOUT_RATE_LIMIT" if degradation_detected else "RESILIENT_WITHIN_BOUNDS"
            )
        )
        session.add_attempt(attempt)

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=resolved_url,
            summary=summary,
            key_insights=insights + [observed_facts, inferred_conclusion],
            raw_data={
                "total_requests": total_requests_sent,
                "initial_rate": initial_rate,
                "peak_rate": max_rate,
                "concurrency": concurrency,
                "baseline_mean_ms": base_mean,
                "mean_latency_ms": mean_all_lat,
                "p95_latency_ms": p95_lat,
                "status_distribution": status_dist,
                "degradation_detected": degradation_detected,
                "rate_limit_detected": rate_limit_detected,
                "threshold_rate": threshold_rate,
                "threshold_reason": threshold_reason,
                "recovery_verified": recovery_verified,
                "recovery_mean_ms": rec_mean,
                "observed_facts": observed_facts,
                "inferred_conclusion": inferred_conclusion,
                "stage_results": stage_results,
                "samples": samples_collected
            }
        )
