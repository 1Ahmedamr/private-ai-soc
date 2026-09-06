# src/incidents/store.py

from typing import Dict, List, Optional
from src.models.incident_schema import Incident


class IncidentStore:
    """
    مخزن مؤقت للـincidents في الذاكرة.

    ليه بنبنيها كـclass منفصل بدل ما نستخدم list/dict عادي في main.py؟
    عشان لما نستبدلها بـdatabase حقيقية (SQLite/PostgreSQL) بعدين،
    نغيّر الملف ده بس - وكل الكود اللي بيستخدم IncidentStore
    (زي correlation engine, API endpoints, dashboard) 
    مش هيحتاج يتغيّر خالص. ده تطبيق مبدأ اسمه "Repository Pattern".
    """

    def __init__(self):
        self._incidents: Dict[str, Incident] = {}
        # فهرسة إضافية بالـcorrelation_key عشان نلاقي incidents سريع
        self._by_correlation_key: Dict[str, str] = {}  # correlation_key -> incident_id

    def save(self, incident: Incident) -> None:
        self._incidents[incident.incident_id] = incident
        self._by_correlation_key[incident.correlation_key] = incident.incident_id

    def get_by_id(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def get_by_correlation_key(self, correlation_key: str) -> Optional[Incident]:
        """
        ده أهم method هنا - بيدور على incident مفتوح بنفس الـcorrelation_key
        عشان نعمل deduplication (منضيفش incident جديد لو فيه واحد مفتوح
        أصلاً لنفس الـuser/IP).
        """
        incident_id = self._by_correlation_key.get(correlation_key)
        if incident_id:
            return self._incidents.get(incident_id)
        return None

    def get_all(self) -> List[Incident]:
        return list(self._incidents.values())

    def get_open_incidents(self) -> List[Incident]:
        from src.models.incident_schema import IncidentStatus
        return [i for i in self._incidents.values() if i.status == IncidentStatus.OPEN]

    def count(self) -> int:
        return len(self._incidents)