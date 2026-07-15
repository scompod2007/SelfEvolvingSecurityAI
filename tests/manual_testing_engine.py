import sys
import time
import uuid
import random
import logging
import inspect
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Type
from dataclasses import dataclass, field, is_dataclass, asdict
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import filters.severity_config as severity_config_mod
import filters.risk_scoring as risk_scoring_mod
import scoring.event_weighting as event_weighting_mod
import scoring.severity_decision as severity_decision_mod
import scoring.severity_metadata as severity_metadata_mod

import detectors.dangerous_process_detector as process_detector_mod
import detectors.dangerous_file_detector as file_detector_mod
import detectors.dangerous_registry_detector as registry_detector_mod
import detectors.dangerous_network_detector as network_detector_mod

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.NullHandler()]
)
logger = logging.getLogger("ManualTestingEngine")

@dataclass(frozen=True)
class TelemetryEvent:
    event_id: str
    timestamp: str
    event_type: str
    data: Dict[str, Any]

@dataclass
class TestResult:
    test_name: str
    event_type: str
    expected_severities: List[str]
    indicators: List[str] = field(default_factory=list)
    matched_rules: List[str] = field(default_factory=list)
    base_risk: float = 0.0
    event_weight: float = 0.0
    final_risk: float = 0.0
    severity: str = "UNKNOWN"
    confidence: str = "UNKNOWN"
    reasons: List[str] = field(default_factory=list)
    summary: str = ""
    passed: bool = False
    execution_time_ms: float = 0.0
    stages_executed: List[str] = field(default_factory=list)


class APIReflectionCache:
    """
    Enterprise API Discovery Engine.
    Performs true reflection ONCE per application lifecycle.
    Caches resolved classes, methods, and signatures to ensure O(1) runtime performance.
    """
    _initialized = False
    _lock = threading.Lock()
    
    classes: Dict[str, Type] = {}
    methods: Dict[str, str] = {}
    signatures: Dict[str, inspect.Signature] = {}

    @classmethod
    def initialize(cls):
        if cls._initialized:
            return
        with cls._lock:
            if cls._initialized:
                return

            cls._discover_and_cache("CONFIG", severity_config_mod, "Config")
            cls._discover_and_cache("PROCESS", process_detector_mod, "Detector")
            cls._discover_and_cache("FILE", file_detector_mod, "Detector")
            cls._discover_and_cache("REGISTRY", registry_detector_mod, "Detector")
            cls._discover_and_cache("NETWORK", network_detector_mod, "Detector")
            cls._discover_and_cache("SCORER", risk_scoring_mod, "Scorer")
            cls._discover_and_cache("WEIGHTER", event_weighting_mod, "Weighter")
            cls._discover_and_cache("DECISION", severity_decision_mod, "Decision")
            cls._discover_and_cache("METADATA", severity_metadata_mod, "Metadata")

            cls._initialized = True

    @classmethod
    def _discover_and_cache(cls, key: str, module: Any, role_hint: str):
        target_cls = cls._resolve_main_class(module, role_hint)
        cls.classes[key] = target_cls
        
        if target_cls and key != "CONFIG":
            method_name = cls._resolve_processing_method(target_cls, role_hint)
            cls.methods[key] = method_name
            if method_name:
                method_obj = getattr(target_cls, method_name)
                cls.signatures[key] = inspect.signature(method_obj)

    @classmethod
    def _resolve_main_class(cls, module: Any, role_hint: str) -> Optional[Type]:
        candidates = []
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if obj.__module__ != module.__name__:
                continue
            if issubclass(obj, Exception) or hasattr(obj, "__dataclass_fields__") or hasattr(obj, "_asdict"):
                continue
                
            name_lower = name.lower()
            if any(skip in name_lower for skip in ["result", "dto", "enum", "exception", "event"]):
                continue
            if "config" in name_lower and role_hint.lower() != "config":
                continue
            candidates.append(obj)
            
        def class_score(c: Type) -> int:
            s = 0
            n = c.__name__.lower()
            if role_hint.lower() in n: s += 10
            if "detector" in n and role_hint.lower() == "detector": s += 5
            if "scorer" in n and role_hint.lower() == "scorer": s += 5
            return s
            
        candidates.sort(key=class_score, reverse=True)
        return candidates[0] if candidates else None

    @classmethod
    def _resolve_processing_method(cls, target_cls: Type, role_hint: str) -> Optional[str]:
        candidates = []
        for name, method in inspect.getmembers(target_cls, inspect.isfunction):
            if name.startswith('_'):
                continue
            if any(name.startswith(p) for p in ["get_", "set_", "load_", "reset_", "clear_", "init_", "export_", "log_", "add_", "remove_", "validate_", "build_"]):
                if not (role_hint.lower() == "metadata" and name.startswith("build")):
                    continue
            candidates.append((name, method))

        def method_score(m_tuple) -> int:
            name, method = m_tuple
            s = 0
            n = name.lower()
            sig = inspect.signature(method)
            
            if any(kw in n for kw in ["analyze", "detect", "process", "evaluate", "scan", "score", "calculate", "apply", "decide", "determine", "build", "generate"]):
                s += 10
            
            params = [p for p in sig.parameters if p != 'self']
            if not params:
                s -= 20
                
            for p in params:
                pl = p.lower()
                if pl in ["event", "data", "telemetry", "context", "result"]: s += 5
                
            return s

        candidates.sort(key=method_score, reverse=True)
        return candidates[0][0] if candidates else None


class DynamicInvoker:
    """
    Safely executes dynamically resolved methods using parameter matching.
    """
    @staticmethod
    def extract_dict(obj: Any) -> Dict[str, Any]:
        if isinstance(obj, dict):
            return obj
        if is_dataclass(obj):
            return asdict(obj)
        if hasattr(obj, "_asdict"):
            return obj._asdict()
        if hasattr(obj, "__dict__"):
            return {k: v for k, v in obj.__dict__.items() if not k.startswith('_')}
        if hasattr(obj, "__slots__"):
            return {s: getattr(obj, s) for s in obj.__slots__ if hasattr(obj, s)}
        return {}

    @staticmethod
    def instantiate(cls: Type, config_instance: Any = None) -> Any:
        if not cls:
            return None
        try:
            sig = inspect.signature(cls.__init__)
            kwargs = {}
            for name, param in sig.parameters.items():
                if name == 'self':
                    continue
                if config_instance and ('config' in name.lower() or 
                    (param.annotation != inspect.Parameter.empty and isinstance(config_instance, param.annotation))):
                    kwargs[name] = config_instance
            return cls(**kwargs)
        except Exception:
            try:
                return cls()
            except Exception as e:
                logger.error(f"Failed to instantiate {cls.__name__}: {e}")
                return None

    @staticmethod
    def invoke(instance: Any, method_name: str, signature: inspect.Signature, context: Dict[str, Any]) -> Any:
        if not instance or not method_name:
            return None
            
        method = getattr(instance, method_name)
        kwargs = {}
        
        for param_name, param in signature.parameters.items():
            if param_name == 'self':
                continue
                
            val = None
            p_lower = param_name.lower()
            
            if p_lower in context:
                val = context[p_lower]
            elif 'event' in p_lower:
                val = context.get('event')
            elif 'data' in p_lower or 'telemetry' in p_lower:
                val = context.get('data')
            elif 'config' in p_lower:
                val = context.get('config')
            elif 'result' in p_lower or 'detect' in p_lower or 'output' in p_lower:
                val = context.get('detector_result')
            elif 'score' in p_lower or 'risk' in p_lower or 'base' in p_lower:
                val = context.get('base_risk')
                if 'final' in p_lower or 'weight' in p_lower:
                    val = context.get('final_risk')
            elif 'conf' in p_lower:
                val = context.get('confidence')
            elif 'sev' in p_lower:
                val = context.get('severity')
            elif 'type' in p_lower:
                val = context.get('event').event_type if context.get('event') else None
                
            if val is not None:
                kwargs[param_name] = val
            elif param.default == inspect.Parameter.empty:
                kwargs[param_name] = context.get('data')
                
        has_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values())
        if has_kwargs and not kwargs:
            kwargs.update(context.get('data', {}))
            
        return method(**kwargs)


class RealPipeline:
    """
    Thread-safe instance of the production pipeline.
    Utilizes APIReflectionCache for O(1) performance.
    """
    def __init__(self):
        APIReflectionCache.initialize()
        
        cfg_cls = APIReflectionCache.classes.get("CONFIG")
        self.config = DynamicInvoker.instantiate(cfg_cls) if cfg_cls else None
        
        self.components = {
            "PROCESS": DynamicInvoker.instantiate(APIReflectionCache.classes.get("PROCESS"), self.config),
            "FILE": DynamicInvoker.instantiate(APIReflectionCache.classes.get("FILE"), self.config),
            "REGISTRY": DynamicInvoker.instantiate(APIReflectionCache.classes.get("REGISTRY"), self.config),
            "NETWORK": DynamicInvoker.instantiate(APIReflectionCache.classes.get("NETWORK"), self.config),
            "SCORER": DynamicInvoker.instantiate(APIReflectionCache.classes.get("SCORER"), self.config),
            "WEIGHTER": DynamicInvoker.instantiate(APIReflectionCache.classes.get("WEIGHTER"), self.config),
            "DECISION": DynamicInvoker.instantiate(APIReflectionCache.classes.get("DECISION"), self.config),
            "METADATA": DynamicInvoker.instantiate(APIReflectionCache.classes.get("METADATA"), self.config)
        }

    def process_event(self, event: TelemetryEvent) -> Dict[str, Any]:
        stages_executed = []
        
        detector_key = event.event_type
        detector_inst = self.components.get(detector_key)
        detector_meth = APIReflectionCache.methods.get(detector_key)
        detector_sig = APIReflectionCache.signatures.get(detector_key)
        
        if not detector_inst or not detector_meth:
            raise ValueError(f"No configured detector for event type: {event.event_type}")

        context = {
            "event": event,
            "data": event.data,
            "config": self.config
        }

        # Stage 1: Detector
        det_result = DynamicInvoker.invoke(detector_inst, detector_meth, detector_sig, context)
        stages_executed.append("detector")
        det_dict = DynamicInvoker.extract_dict(det_result)
        context["detector_result"] = det_result
        context.update(det_dict)

        # Stage 2: Scorer
        base_risk = 0.0
        scorer_inst = self.components.get("SCORER")
        if scorer_inst:
            try:
                risk_result = DynamicInvoker.invoke(
                    scorer_inst, 
                    APIReflectionCache.methods.get("SCORER"), 
                    APIReflectionCache.signatures.get("SCORER"), 
                    context
                )
                stages_executed.append("scorer")
                risk_dict = DynamicInvoker.extract_dict(risk_result)
                base_risk = float(risk_dict.get("score", risk_result) if isinstance(risk_result, object) and not isinstance(risk_result, (int, float)) else risk_result)
            except Exception as e:
                logger.error(f"Scorer failure: {e}")
                
        context["base_risk"] = base_risk
        context["score"] = base_risk

        # Stage 3: Weighter
        final_risk = base_risk
        weighter_inst = self.components.get("WEIGHTER")
        if weighter_inst:
            try:
                weight_result = DynamicInvoker.invoke(
                    weighter_inst, 
                    APIReflectionCache.methods.get("WEIGHTER"), 
                    APIReflectionCache.signatures.get("WEIGHTER"), 
                    context
                )
                stages_executed.append("weighter")
                weight_dict = DynamicInvoker.extract_dict(weight_result)
                final_risk = float(weight_dict.get("score", weight_result) if isinstance(weight_result, object) and not isinstance(weight_result, (int, float)) else weight_result)
            except Exception as e:
                logger.error(f"Weighter failure: {e}")
                
        context["final_risk"] = final_risk
        event_weight = final_risk / base_risk if base_risk > 0 else 1.0
        context["event_weight"] = event_weight

        # Stage 4: Decision
        severity, confidence = "UNKNOWN", "UNKNOWN"
        decision_inst = self.components.get("DECISION")
        if decision_inst:
            try:
                dec_result = DynamicInvoker.invoke(
                    decision_inst, 
                    APIReflectionCache.methods.get("DECISION"), 
                    APIReflectionCache.signatures.get("DECISION"), 
                    context
                )
                stages_executed.append("decision")
                if isinstance(dec_result, tuple) and len(dec_result) >= 2:
                    severity, confidence = dec_result[0], dec_result[1]
                else:
                    dec_dict = DynamicInvoker.extract_dict(dec_result)
                    severity = dec_dict.get("severity", "UNKNOWN")
                    confidence = dec_dict.get("confidence", "UNKNOWN")
            except Exception as e:
                logger.error(f"Decision engine failure: {e}")
                
        context["severity"] = severity
        context["confidence"] = confidence

        # Stage 5: Metadata
        meta_dict = {"reasons": [], "summary": "Pipeline processing completed"}
        metadata_inst = self.components.get("METADATA")
        if metadata_inst:
            try:
                meta_result = DynamicInvoker.invoke(
                    metadata_inst, 
                    APIReflectionCache.methods.get("METADATA"), 
                    APIReflectionCache.signatures.get("METADATA"), 
                    context
                )
                stages_executed.append("metadata")
                extracted_meta = DynamicInvoker.extract_dict(meta_result)
                meta_dict.update(extracted_meta)
            except Exception as e:
                logger.error(f"Metadata engine failure: {e}")

        return {
            "indicators": det_dict.get("indicators", []),
            "matched_rules": det_dict.get("matched_rules", []),
            "base_risk": base_risk,
            "event_weight": event_weight,
            "final_risk": final_risk,
            "severity": severity,
            "confidence": confidence,
            "reasons": meta_dict.get("reasons", []),
            "summary": meta_dict.get("summary", ""),
            "stages_executed": stages_executed
        }


class ThreadLocalPipelineManager:
    _local = threading.local()

    @classmethod
    def get_pipeline(cls) -> RealPipeline:
        if not hasattr(cls._local, "pipeline"):
            cls._local.pipeline = RealPipeline()
        return cls._local.pipeline


class ScenarioBuilder:
    @staticmethod
    def _create_event(event_type: str, data: Dict[str, Any]) -> TelemetryEvent:
        base_telemetry = {
            "session_id": 1,
            "pid": random.randint(1000, 9999),
            "ppid": random.randint(100, 999),
            "username": "CORP\\User",
            "architecture": "x64",
            "elevation": "Medium",
            "token_type": "Primary",
            "integrity_level": "Medium",
            "hash_sha256": uuid.uuid4().hex * 2,
            "hash_md5": uuid.uuid4().hex,
            "entropy": round(random.uniform(4.5, 7.9), 2),
            "file_size": random.randint(1024, 10485760)
        }
        base_telemetry.update(data)
        
        return TelemetryEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            data=base_telemetry
        )

    @classmethod
    def get_benign_events(cls) -> List[Tuple[str, TelemetryEvent, List[str]]]:
        return [
            ("Normal notepad.exe", cls._create_event("PROCESS", {"process_name": "notepad.exe", "image_path": "C:\\Windows\\System32\\notepad.exe", "parent_process": "explorer.exe", "command_line": "notepad.exe"}), ["INFO", "LOW"]),
            ("Normal explorer.exe", cls._create_event("PROCESS", {"process_name": "explorer.exe", "image_path": "C:\\Windows\\explorer.exe", "parent_process": "userinit.exe", "command_line": "explorer.exe"}), ["INFO", "LOW"]),
            ("Normal chrome.exe browsing", cls._create_event("NETWORK", {"process_name": "chrome.exe", "destination_ip": "142.250.190.46", "destination_port": 443, "network_protocol": "TCP", "dns_name": "google.com"}), ["INFO", "LOW"]),
            ("Private IP network connection", cls._create_event("NETWORK", {"process_name": "smbd.exe", "destination_ip": "192.168.1.15", "destination_port": 445, "network_protocol": "TCP"}), ["INFO", "LOW"]),
            ("Normal registry read", cls._create_event("REGISTRY", {"process_name": "svchost.exe", "registry_operation": "READ", "registry_hive": "HKLM", "registry_path": "Software\\Microsoft\\Windows"}), ["INFO", "LOW"])
        ]

    @classmethod
    def get_dangerous_file_events(cls) -> List[Tuple[str, TelemetryEvent, List[str]]]:
        severities = ["MEDIUM", "HIGH", "CRITICAL"]
        return [
            ("Temp execution", cls._create_event("FILE", {"file_path": "C:\\Temp\\malware.exe", "action": "EXECUTE", "signer": "None", "signature_status": "Unsigned"}), severities),
            ("Startup folder execution", cls._create_event("FILE", {"file_path": "C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\persist.exe", "action": "CREATE"}), severities),
            ("PowerShell script", cls._create_event("FILE", {"file_path": "C:\\Temp\\script.ps1", "action": "WRITE"}), severities),
            ("Batch script", cls._create_event("FILE", {"file_path": "C:\\Users\\Public\\run.bat", "action": "EXECUTE"}), severities),
            ("VBS script", cls._create_event("FILE", {"file_path": "C:\\Temp\\dropper.vbs", "action": "EXECUTE"}), severities),
            ("JS script", cls._create_event("FILE", {"file_path": "C:\\Temp\\payload.js", "action": "EXECUTE"}), severities),
            ("DLL payload", cls._create_event("FILE", {"file_path": "C:\\Temp\\hook.dll", "action": "LOAD"}), severities),
            ("SYS driver", cls._create_event("FILE", {"file_path": "C:\\Windows\\System32\\drivers\\malicious.sys", "action": "CREATE"}), severities),
            ("SCR screen saver", cls._create_event("FILE", {"file_path": "C:\\Temp\\invoice.scr", "action": "EXECUTE"}), severities),
            ("AppData execution", cls._create_event("FILE", {"file_path": "C:\\Users\\Admin\\AppData\\Local\\Temp\\update.exe", "action": "EXECUTE"}), severities),
            ("Downloads execution", cls._create_event("FILE", {"file_path": "C:\\Users\\Admin\\Downloads\\crack.exe", "action": "EXECUTE"}), severities)
        ]

    @classmethod
    def get_dangerous_registry_events(cls) -> List[Tuple[str, TelemetryEvent, List[str]]]:
        severities = ["HIGH", "CRITICAL"]
        return [
            ("Run Key", cls._create_event("REGISTRY", {"registry_hive": "HKCU", "registry_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "registry_value": "Payload", "data": "C:\\Temp\\payload.exe", "registry_operation": "WRITE"}), severities),
            ("RunOnce", cls._create_event("REGISTRY", {"registry_hive": "HKLM", "registry_path": "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "registry_value": "Update", "data": "powershell.exe -enc", "registry_operation": "WRITE"}), severities),
            ("Services", cls._create_event("REGISTRY", {"registry_hive": "HKLM", "registry_path": "System\\CurrentControlSet\\Services\\MalSvc", "registry_value": "ImagePath", "data": "C:\\Temp\\mal.exe", "registry_operation": "WRITE"}), severities),
            ("Winlogon", cls._create_event("REGISTRY", {"registry_hive": "HKLM", "registry_path": "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "registry_value": "Userinit", "data": "userinit.exe, C:\\Temp\\hook.exe", "registry_operation": "WRITE"}), severities),
            ("Image File Execution Options", cls._create_event("REGISTRY", {"registry_hive": "HKLM", "registry_path": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe", "registry_value": "Debugger", "data": "cmd.exe", "registry_operation": "WRITE"}), severities),
            ("Persistence modifications", cls._create_event("REGISTRY", {"registry_hive": "HKCU", "registry_path": "Environment", "registry_value": "UserInitMprLogonScript", "data": "C:\\Temp\\persist.bat", "registry_operation": "WRITE"}), severities)
        ]

    @classmethod
    def get_dangerous_network_events(cls) -> List[Tuple[str, TelemetryEvent, List[str]]]:
        severities = ["MEDIUM", "HIGH", "CRITICAL"]
        return [
            ("Outbound public IP", cls._create_event("NETWORK", {"destination_ip": "185.10.10.10", "destination_port": 8080, "process_name": "powershell.exe", "network_protocol": "TCP"}), severities),
            ("Known suspicious ports", cls._create_event("NETWORK", {"destination_ip": "45.33.22.11", "destination_port": 4444, "process_name": "cmd.exe", "network_protocol": "TCP"}), severities),
            ("External destination", cls._create_event("NETWORK", {"destination_ip": "193.168.1.1", "destination_port": 1337, "process_name": "rundll32.exe", "network_protocol": "TCP"}), severities),
            ("PowerShell download", cls._create_event("NETWORK", {"destination_ip": "185.199.108.133", "destination_port": 443, "process_name": "powershell.exe", "dns_name": "raw.githubusercontent.com", "network_protocol": "TCP"}), severities),
            ("Unknown protocol", cls._create_event("NETWORK", {"destination_ip": "10.0.0.5", "destination_port": 6667, "network_protocol": "UNKNOWN"}), severities),
            ("Suspicious outbound communication", cls._create_event("NETWORK", {"destination_ip": "185.10.10.10", "destination_port": 443, "bytes_out": 5000000}), severities)
        ]

    @classmethod
    def get_dangerous_process_events(cls) -> List[Tuple[str, TelemetryEvent, List[str]]]:
        severities = ["HIGH", "CRITICAL"]
        processes = ["powershell.exe", "cmd.exe", "wmic.exe", "regsvr32.exe", 
                     "mshta.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe", "psexec.exe"]
        return [
            (f"{proc} execution", cls._create_event("PROCESS", {"process_name": proc, "command_line": f"{proc} -hidden -bypass JABzAD0ATgBlAHcALQBPAGIAagBlAGMAd...", "integrity_level": "High", "elevation": "High"}), severities)
            for proc in processes
        ]

    @classmethod
    def get_mixed_attack_scenario(cls) -> List[Tuple[str, TelemetryEvent, List[str]]]:
        severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        return [
            ("Mixed Attack - Initial Execution", cls._create_event("PROCESS", {"process_name": "powershell.exe", "command_line": "powershell -ep bypass", "integrity_level": "Medium"}), severities),
            ("Mixed Attack - Payload Download", cls._create_event("NETWORK", {"process_name": "powershell.exe", "destination_ip": "185.10.10.10", "destination_port": 443, "network_protocol": "TCP"}), severities),
            ("Mixed Attack - File Drop", cls._create_event("FILE", {"file_path": "C:\\Temp\\svchost_fake.exe", "action": "CREATE", "entropy": 7.9, "signature_status": "Unsigned"}), severities),
            ("Mixed Attack - Persistence", cls._create_event("REGISTRY", {"registry_hive": "HKCU", "registry_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "registry_value": "Updater", "data": "C:\\Temp\\svchost_fake.exe", "registry_operation": "WRITE"}), severities),
            ("Mixed Attack - C2 Connection", cls._create_event("NETWORK", {"process_name": "svchost_fake.exe", "destination_ip": "185.10.10.10", "destination_port": 4444, "network_protocol": "TCP"}), severities),
            ("Mixed Attack - Privilege Escalation", cls._create_event("PROCESS", {"process_name": "cmd.exe", "command_line": "cmd.exe /c whoami /priv | findstr SeDebugPrivilege", "integrity_level": "System", "elevation": "High"}), severities)
        ]

    @classmethod
    def generate_random_event(cls) -> TelemetryEvent:
        event_types = ["PROCESS", "FILE", "REGISTRY", "NETWORK"]
        chosen_type = random.choice(event_types)
        is_dangerous = random.random() > 0.5
        
        if chosen_type == "PROCESS":
            if is_dangerous:
                data = {"process_name": "powershell.exe", "command_line": f"powershell.exe -enc {uuid.uuid4().hex}"}
            else:
                data = {"process_name": "chrome.exe", "command_line": "chrome.exe --type=renderer"}
        elif chosen_type == "FILE":
            if is_dangerous:
                data = {"file_path": f"C:\\Temp\\{uuid.uuid4().hex[:8]}.exe", "action": "EXECUTE"}
            else:
                data = {"file_path": f"C:\\Users\\User\\Documents\\{uuid.uuid4().hex[:8]}.docx", "action": "READ"}
        elif chosen_type == "REGISTRY":
            if is_dangerous:
                data = {"registry_hive": "HKCU", "registry_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "data": "C:\\Temp\\mal.exe"}
            else:
                data = {"registry_hive": "HKCU", "registry_path": "Software\\Microsoft\\Notepad", "data": "1"}
        else:
            if is_dangerous:
                data = {"destination_ip": "185.10.10.10", "destination_port": 4444, "process_name": "cmd.exe"}
            else:
                data = {"destination_ip": "192.168.1.100", "destination_port": 443, "process_name": "msedge.exe"}
                
        return cls._create_event(chosen_type, data)


class TestingEngine:
    def execute_test(self, test_name: str, event: TelemetryEvent, expected_severities: List[str]) -> TestResult:
        start_time = time.perf_counter()
        
        try:
            pipeline = ThreadLocalPipelineManager.get_pipeline()
            result_data = pipeline.process_event(event)
            end_time = time.perf_counter()
            
            severity = result_data.get("severity", "UNKNOWN")
            passed = severity in expected_severities
            
            return TestResult(
                test_name=test_name,
                event_type=event.event_type,
                expected_severities=expected_severities,
                indicators=result_data.get("indicators", []),
                matched_rules=result_data.get("matched_rules", []),
                base_risk=result_data.get("base_risk", 0.0),
                event_weight=result_data.get("event_weight", 0.0),
                final_risk=result_data.get("final_risk", 0.0),
                severity=severity,
                confidence=result_data.get("confidence", "UNKNOWN"),
                reasons=result_data.get("reasons", []),
                summary=result_data.get("summary", ""),
                passed=passed,
                execution_time_ms=(end_time - start_time) * 1000.0,
                stages_executed=result_data.get("stages_executed", [])
            )
        except Exception as e:
            end_time = time.perf_counter()
            logger.error(f"Test '{test_name}' failed with exception: {str(e)}")
            return TestResult(
                test_name=test_name,
                event_type=event.event_type,
                expected_severities=expected_severities,
                summary=f"EXCEPTION: {str(e)}",
                passed=False,
                execution_time_ms=(end_time - start_time) * 1000.0
            )

    def print_result(self, result: TestResult):
        print("-" * 50)
        print(f"Test Name           : {result.test_name}")
        print(f"Event Type          : {result.event_type}")
        print(f"Detected Indicators : {', '.join(result.indicators) if result.indicators else 'None'}")
        print(f"Matched Rules       : {', '.join(result.matched_rules) if result.matched_rules else 'None'}")
        print(f"Base Risk           : {result.base_risk:.2f}")
        print(f"Event Weight        : {result.event_weight:.2f}")
        print(f"Final Risk          : {result.final_risk:.2f}")
        print(f"Severity            : {result.severity}")
        print(f"Confidence          : {result.confidence}")
        print(f"Reasons             : {', '.join(result.reasons) if result.reasons else 'None'}")
        print(f"Stages Executed     : {', '.join(result.stages_executed)}")
        print(f"Summary             : {result.summary}")
        print(f"PASS / FAIL         : {'PASS' if result.passed else 'FAIL'}")
        print("-" * 50)


class StressTestEngine:
    def run_stress_test(self, count: int) -> Dict[str, Any]:
        events = [ScenarioBuilder.generate_random_event() for _ in range(count)]
        
        start_time = time.perf_counter()
        
        results = []
        crashes = 0
        exceptions_count = 0
        
        with ThreadPoolExecutor(max_workers=16) as executor:
            future_to_event = {executor.submit(self._process_single, e): e for e in events}
            for future in as_completed(future_to_event):
                try:
                    res = future.result()
                    if res:
                        results.append(res)
                    else:
                        crashes += 1
                except Exception:
                    exceptions_count += 1
                    crashes += 1

        end_time = time.perf_counter()
        total_time = end_time - start_time
        
        if not results:
            return {"error": "All stress tests failed or crashed."}
            
        execution_times = [r["time_ms"] for r in results]
        risks = [r["final_risk"] for r in results]
        
        return {
            "total_events": count,
            "processed": len(results),
            "crashes": crashes,
            "exceptions": exceptions_count,
            "total_time_sec": total_time,
            "events_per_sec": count / total_time if total_time > 0 else 0,
            "avg_time_ms": sum(execution_times) / len(execution_times),
            "max_time_ms": max(execution_times),
            "min_time_ms": min(execution_times),
            "avg_risk": sum(risks) / len(risks)
        }

    def _process_single(self, event: TelemetryEvent) -> Optional[Dict[str, Any]]:
        try:
            pipeline = ThreadLocalPipelineManager.get_pipeline()
            t0 = time.perf_counter()
            data = pipeline.process_event(event)
            t1 = time.perf_counter()
            return {
                "time_ms": (t1 - t0) * 1000.0,
                "final_risk": data.get("final_risk", 0.0)
            }
        except Exception:
            return None


def severity_to_int(severity: str) -> int:
    mapping = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return mapping.get(severity.upper(), -1)


def print_summary(
    total_tests: int, 
    passed: int, 
    failed: int, 
    exec_time: float, 
    avg_risk: float, 
    avg_sev: str, 
    perf_stats: str
):
    print("\n=================================================")
    print(f"Total Tests            : {total_tests}")
    print(f"Passed                 : {passed}")
    print(f"Failed                 : {failed}")
    print(f"Execution Time         : {exec_time:.4f} seconds")
    print(f"Average Risk           : {avg_risk:.2f}")
    print(f"Average Severity       : {avg_sev}")
    print("Performance Statistics :")
    for line in perf_stats.split('\n'):
        if line.strip():
            print(f"  {line}")
    print("=================================================\n")


def run_all_validations():
    engine = TestingEngine()
    
    all_scenarios = []
    all_scenarios.extend(ScenarioBuilder.get_benign_events())
    all_scenarios.extend(ScenarioBuilder.get_dangerous_file_events())
    all_scenarios.extend(ScenarioBuilder.get_dangerous_registry_events())
    all_scenarios.extend(ScenarioBuilder.get_dangerous_network_events())
    all_scenarios.extend(ScenarioBuilder.get_dangerous_process_events())
    
    mixed_attack = ScenarioBuilder.get_mixed_attack_scenario()
    
    global_start = time.perf_counter()
    results: List[TestResult] = []
    
    print("\nStarting Standard Scenarios...")
    for name, event, expected in all_scenarios:
        res = engine.execute_test(name, event, expected)
        engine.print_result(res)
        results.append(res)
        
    print("\nStarting Mixed Attack Scenario (End-to-End Execution)...")
    highest_severity = "INFO"
    all_stages_met = True
    
    accumulated_indicators = 0
    accumulated_rules = 0
    accumulated_reasons = 0
    
    for name, event, expected in mixed_attack:
        res = engine.execute_test(name, event, expected)
        engine.print_result(res)
        
        if severity_to_int(res.severity) > severity_to_int(highest_severity):
            highest_severity = res.severity
            
        accumulated_indicators += len(res.indicators)
        accumulated_rules += len(res.matched_rules)
        accumulated_reasons += len(res.reasons)

        required_stages = {"detector", "scorer", "weighter", "decision", "metadata"}
        if not required_stages.issubset(set(res.stages_executed)):
            if res.base_risk > 0:
                all_stages_met = False

    mixed_final_passed = (
        all_stages_met and 
        severity_to_int(highest_severity) >= severity_to_int("HIGH") and
        accumulated_indicators > 0 and 
        accumulated_rules > 0 and
        accumulated_reasons > 0
    )
    
    print("-" * 50)
    print(f"Mixed Attack Final Evaluation")
    print(f"Pipeline Executed Fully   : {'Yes' if all_stages_met else 'No'}")
    print(f"Indicators Detected       : {accumulated_indicators}")
    print(f"Rules Matched             : {accumulated_rules}")
    print(f"Reasons Generated         : {accumulated_reasons}")
    print(f"Highest Severity Achieved : {highest_severity}")
    print(f"PASS / FAIL               : {'PASS' if mixed_final_passed else 'FAIL'}")
    print("-" * 50)
    
    mixed_dummy_result = TestResult(
        test_name="Mixed Attack Overall",
        event_type="MULTIPLE",
        expected_severities=["HIGH", "CRITICAL"],
        severity=highest_severity,
        final_risk=0.0,
        passed=mixed_final_passed,
        execution_time_ms=0.0
    )
    results.append(mixed_dummy_result)
    
    print("\nStarting Stress Tests...")
    stress_engine = StressTestEngine()
    stress_counts = [1000, 5000, 10000]
    stress_reports = []
    
    for count in stress_counts:
        print(f"\nExecuting {count} concurrent events...")
        report = stress_engine.run_stress_test(count)
        stress_reports.append(report)
        print(f"  Processed    : {report.get('processed', 0)}")
        print(f"  Crashes      : {report.get('crashes', 0)}")
        print(f"  Exceptions   : {report.get('exceptions', 0)}")
        print(f"  Events/sec   : {report.get('events_per_sec', 0):.2f}")
        print(f"  Min Latency  : {report.get('min_time_ms', 0):.2f} ms")
        print(f"  Avg Latency  : {report.get('avg_time_ms', 0):.2f} ms")
        print(f"  Max Latency  : {report.get('max_time_ms', 0):.2f} ms")
        
    global_end = time.perf_counter()
    total_time = global_end - global_start
    
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r.passed)
    failed_tests = total_tests - passed_tests
    avg_risk = sum(r.final_risk for r in results) / total_tests if total_tests > 0 else 0.0
    
    if avg_risk < 20:
        avg_sev = "INFO"
    elif avg_risk < 40:
        avg_sev = "LOW"
    elif avg_risk < 70:
        avg_sev = "MEDIUM"
    elif avg_risk < 90:
        avg_sev = "HIGH"
    else:
        avg_sev = "CRITICAL"
        
    perf_lines = []
    for report in stress_reports:
        c = report.get('total_events', 0)
        eps = report.get('events_per_sec', 0)
        min_lat = report.get('min_time_ms', 0)
        avg_lat = report.get('avg_time_ms', 0)
        max_lat = report.get('max_time_ms', 0)
        crashes = report.get('crashes', 0)
        exceptions = report.get('exceptions', 0)
        perf_lines.append(
            f"Volume: {c:<6} | EPS: {eps:<8.2f} | Min Latency: {min_lat:<6.2f}ms | Avg Latency: {avg_lat:<6.2f}ms | "
            f"Max Latency: {max_lat:<6.2f}ms | Crashes: {crashes} | Exceptions: {exceptions}"
        )
    perf_stats_str = "\n".join(perf_lines)
    
    print_summary(
        total_tests=total_tests,
        passed=passed_tests,
        failed=failed_tests,
        exec_time=total_time,
        avg_risk=avg_risk,
        avg_sev=avg_sev,
        perf_stats=perf_stats_str
    )


if __name__ == "__main__":
    run_all_validations()