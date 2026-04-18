from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, request

from .engine.workflow import run_pipeline, run_pipeline_csv_dataset, run_pipeline_dataset


DEFAULT_DATASET = str(Path(__file__).resolve().parents[1] / "dataset" / "incident_examples_min.json")
DEFAULT_INPUT = str(Path(__file__).resolve().parents[1] / "data" / "sample_incident.json")


def create_frontend_api_app() -> Flask:
    app = Flask(__name__)

    @app.after_request
    def _apply_cors_headers(response):  # type: ignore[no-untyped-def]
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return response

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"ok": True, "service": "frontend-payload-api", "framework": "flask"})

    @app.route("/api/frontend-payload", methods=["GET"])
    def frontend_payload():
        dataset_file = request.args.get("dataset_file", DEFAULT_DATASET)
        dataset_index = request.args.get("dataset_index", default=0, type=int)
        input_file = request.args.get("input_file", "")
        csv_file = request.args.get("csv_file", "")
        csv_row_index = request.args.get("csv_row_index", default=0, type=int)

        try:
            if csv_file:
                result = run_pipeline_csv_dataset(csv_file=csv_file, row_index=csv_row_index)
            elif input_file:
                result = run_pipeline(input_file=input_file)
            else:
                result = run_pipeline_dataset(dataset_file=dataset_file, sample_index=dataset_index)
            return jsonify(result)
        except Exception as exc:  # pragma: no cover - defensive API boundary
            return (
                jsonify(
                {
                    "error": "frontend_payload_failed",
                    "message": str(exc),
                    "frontend_payload": {},
                }
                ),
                500,
            )

    return app


def run_frontend_api_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    app = create_frontend_api_app()
    print(f"[FrontendAPI] serving at http://{host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False)
