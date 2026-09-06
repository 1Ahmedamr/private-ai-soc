# src/incidents/correlation_key.py

from typing import List
from src.models.event_schema import NormalizedEvent


def extract_correlation_key(events: List[NormalizedEvent]) -> str:
    """
    يحدد الـidentity المشتركة بين مجموعة events عشان نستخدمها
    كـ"مفتاح" لتجميعهم في نفس الـIncident.

    ترتيب الأولوية:
    1. user (لو موجود لكل الـevents)
    2. src_ip (fallback لو الـuser مش متاح)
    3. host (fallback تاني)
    4. "unknown" (آخر حل - لسه أفضل من رفض الـevent تمامًا،
       زي ما اتفقنا في يوم الـNormalization)
    """
    if not events:
        return "unknown"

    first_event = events[0]

    if first_event.user:
        return f"user:{first_event.user}"
    if first_event.src_ip:
        return f"ip:{first_event.src_ip}"
    if first_event.host:
        return f"host:{first_event.host}"

    return "unknown"