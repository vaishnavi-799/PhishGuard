"""FastAPI application. Run:  uvicorn app.main:app --host 127.0.0.1 --port 8000"""
from __future__ import annotations

import hmac
import logging
import threading
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request

from app import __version__
from app.config import Settings
from app.modeling import ModelNotFoundError
from app.schemas import AnalyzeRequest, PredictRequest, PredictResponse
from app.service import PredictionService
from analysis.config import AnalysisConfig
from analysis.engine import AnalysisEngine
from features.url_features import InvalidUrlError

log = logging.getLogger("ml.api")


def create_app(settings: Settings | None = None, engine: AnalysisEngine | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.service, app.state.load_error = None, None
        try:
            app.state.service = PredictionService.load(settings.model_dir)
            log.info("Loaded model %s (%s explanations)", app.state.service.bundle.version, app.state.service.explainer.method)
        except ModelNotFoundError as e:  # the service still starts so /health can report the problem
            app.state.load_error = str(e)
            log.warning("No model loaded: %s", e)
        app.state.engine = engine or AnalysisEngine(AnalysisConfig.from_env(), predictor=lambda u, sec: (app.state.service.predict(u, sec, top_k=8) if app.state.service else None))
        app.state.slots = threading.BoundedSemaphore(app.state.engine.cfg.max_concurrent)
        if not settings.api_key:
            log.warning("ML_API_KEY is not set: the API is unauthenticated. Do not expose it beyond localhost.")
        yield

    app = FastAPI(title="PhishGuard ML Service", version=__version__, lifespan=lifespan)

    def require_key(x_api_key: str | None = Header(default=None)) -> None:
        if settings.api_key and not (x_api_key and hmac.compare_digest(x_api_key.encode(), settings.api_key.encode())):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

    def service(request: Request) -> PredictionService:
        svc = request.app.state.service
        if svc is None:
            raise HTTPException(status_code=503, detail=request.app.state.load_error or "Model not loaded")
        return svc

    @app.get("/health")
    def health(request: Request):
        svc = request.app.state.service
        return {"status": "ok" if svc else "degraded", "model_loaded": svc is not None, "model_version": svc.bundle.version if svc else None, "detail": request.app.state.load_error}

    @app.get("/model", dependencies=[Depends(require_key)])
    def model_info(svc: PredictionService = Depends(service)):
        return svc.info()

    @app.post("/predict", response_model=PredictResponse, dependencies=[Depends(require_key)])
    def predict(req: PredictRequest, svc: PredictionService = Depends(service)):
        try:  # plain `def`: FastAPI runs it in a worker thread, so CPU-bound inference does not block the event loop
            return svc.predict(req.url, req.security_features, req.top_k, req.explain)
        except ValueError as e:  # includes InvalidUrlError
            raise HTTPException(status_code=422, detail=str(e)) from None

    @app.post("/analyze", dependencies=[Depends(require_key)])
    def analyze(req: AnalyzeRequest, request: Request):
        """Full security analysis of a URL: lexical, DNS/RDAP, TLS, page content, typosquatting, homograph, brand, risk (+ ML when a model is loaded)."""
        slots = request.app.state.slots
        if not slots.acquire(blocking=False):  # each analysis makes outbound requests: cap concurrency
            raise HTTPException(status_code=429, detail="Analysis capacity reached, retry shortly")
        try:  # plain `def` => worker thread; the engine enforces its own wall-clock budget
            return request.app.state.engine.analyze(req.url, inspect_website=req.inspect_website, include_ml=req.include_ml)
        except InvalidUrlError as e:
            raise HTTPException(status_code=422, detail=str(e)) from None
        finally:
            slots.release()

    return app


app = create_app()
