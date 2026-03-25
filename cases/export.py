"""
Phase 7 — Case Export Engine

Read-only export of case data. JSON, PDF, and ZIP formats.
No mutations. No raw file content in exports.
"""

import io
import json
import os
import zipfile
from datetime import datetime

from django.http import HttpResponse, JsonResponse
from django.utils import timezone

from .metrics import get_workspace_mttr, get_workspace_sla_compliance
from .selectors import get_case_mitre_techniques

TIMELINE_EXPORT_LIMIT = 5000


def _serialize_dt(dt):
    """Return ISO string or None."""
    if dt is None:
        return None
    if isinstance(dt, datetime) and hasattr(dt, "isoformat"):
        return dt.isoformat()
    return str(dt)


def export_case_json(case, actor=None):
    """
    Return structured dict for case export. Read-only.
    Does NOT include raw file content. Attachments: filename, uploaded_at, uploaded_by, file_type only.
    """
    mttr = get_workspace_mttr(case.workspace)
    sla = get_workspace_sla_compliance(case.workspace)

    alerts_list = []
    for ca in case.case_alerts.select_related("alert").all():
        a = ca.alert
        alerts_list.append({
            "id": a.id,
            "title": a.title,
            "severity": a.severity,
            "status": a.status,
            "source": a.source,
            "mitre_technique": a.mitre_technique,
            "created_at": _serialize_dt(a.created_at),
        })

    notes_list = []
    for n in case.notes.all():
        notes_list.append({
            "id": n.id,
            "content": n.content,
            "is_internal": n.is_internal,
            "author_id": n.author_id,
            "created_at": _serialize_dt(n.created_at),
        })

    tasks_list = []
    for t in case.tasks.all():
        tasks_list.append({
            "id": t.id,
            "title": t.title,
            "is_completed": t.is_completed,
            "completed_by_id": t.completed_by_id,
            "completed_at": _serialize_dt(t.completed_at),
            "created_at": _serialize_dt(t.created_at),
        })

    iocs_list = []
    for i in case.iocs.all():
        iocs_list.append({
            "id": i.id,
            "type": i.type,
            "value": i.value,
            "enrichment_status": i.enrichment_status,
            "created_at": _serialize_dt(i.created_at),
        })

    attachments_list = []
    for att in case.attachments.all():
        filename = None
        if att.file and att.file.name:
            filename = os.path.basename(str(att.file.name))
        attachments_list.append({
            "filename": filename,
            "file_type": att.file_type,
            "uploaded_at": _serialize_dt(att.uploaded_at),
            "uploaded_by": att.uploaded_by_id,
        })

    activities_qs = case.activities.select_related("actor").order_by("-created_at")
    timeline_truncated = activities_qs.count() > TIMELINE_EXPORT_LIMIT
    recent = list(activities_qs[:TIMELINE_EXPORT_LIMIT])
    recent.reverse()  # chronological for display
    timeline_list = []
    for act in recent:
        actor_display = None
        if act.actor:
            actor_display = act.actor.get_full_name() or act.actor.get_username()
        timeline_list.append({
            "id": act.id,
            "action_type": act.action_type,
            "actor_id": act.actor_id,
            "actor": actor_display or "System",
            "metadata": act.metadata,
            "created_at": _serialize_dt(act.created_at),
        })

    mitre = get_case_mitre_techniques(case)
    now_iso = timezone.now().isoformat()

    result = {
        "exported_at": now_iso,
        "export_metadata": {
            "exported_at": now_iso,
            "exported_by": actor.id if actor else None,
            "system_version": "AEGISPHERE v1.0",
        },
        "timeline_truncated": timeline_truncated,
        "case": {
            "id": case.id,
            "title": case.title,
            "description": case.description,
            "severity": case.severity,
            "priority": case.priority,
            "status": case.status,
            "outcome": case.outcome,
            "sla_deadline": _serialize_dt(case.sla_deadline),
            "sla_breached": case.sla_breached,
            "created_at": _serialize_dt(case.created_at),
            "closed_at": _serialize_dt(case.closed_at),
            "closed_by": case.closed_by_id,
            "resolution_summary": getattr(case, "resolution_summary", "") or "",
            "external_reference_id": getattr(case, "external_reference_id", None),
            "reported_externally": getattr(case, "reported_externally", False),
            "compliance_notes": getattr(case, "compliance_notes", "") or "",
            "reported_at": _serialize_dt(getattr(case, "reported_at", None)),
        },
        "alerts": alerts_list,
        "notes": notes_list,
        "tasks": tasks_list,
        "iocs": iocs_list,
        "attachments": attachments_list,
        "timeline": timeline_list,
        "mitre_techniques": mitre,
        "metrics_snapshot": {
            "mttr_hours": mttr,
            "sla_compliance": sla,
        },
    }
    return result


def export_case_pdf(case, actor=None):
    """
    Render case to PDF via WeasyPrint. Returns HttpResponse with application/pdf.
    """
    from django.template.loader import render_to_string
    from weasyprint import HTML

    data = export_case_json(case, actor=actor)
    context = {"case": case, "data": data}
    html = render_to_string("cases/case_export.html", context)
    pdf_bytes = HTML(string=html).write_pdf()

    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    filename = f"case_{case.id}.pdf"
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    response["X-Content-Type-Options"] = "nosniff"
    return response


def export_case(case, format_type, actor=None):
    """
    Export case in requested format.

    format_type: "json" | "pdf" | "both"

    Returns:
      - "json": JsonResponse
      - "pdf": HttpResponse (application/pdf)
      - "both": HttpResponse (application/zip) with case_<id>.json and case_<id>.pdf
    """
    if format_type == "json":
        data = export_case_json(case, actor=actor)
        response = JsonResponse(data, json_dumps_params={"indent": 2})
        response["Content-Disposition"] = f'attachment; filename="case_{case.id}.json"'
        response["X-Content-Type-Options"] = "nosniff"
        return response

    if format_type == "pdf":
        return export_case_pdf(case, actor=actor)

    if format_type == "both":
        data = export_case_json(case, actor=actor)
        json_str = json.dumps(data, indent=2)

        from django.template.loader import render_to_string
        from weasyprint import HTML

        context = {"case": case, "data": data}
        html = render_to_string("cases/case_export.html", context)
        pdf_bytes = HTML(string=html).write_pdf()

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"case_{case.id}.json", json_str)
            zf.writestr(f"case_{case.id}.pdf", pdf_bytes)

        response = HttpResponse(
            buffer.getvalue(),
            content_type="application/zip",
        )
        response["Content-Disposition"] = f'attachment; filename="case_{case.id}.zip"'
        response["X-Content-Type-Options"] = "nosniff"
        return response

    raise ValueError("format must be 'json', 'pdf', or 'both'")

