from __future__ import annotations
from .domain import ConflictError, ValidationError
TITLE='建筑抗震鉴定与加固排序'; ENTITY='抗震鉴定'; ID_PREFIX='SR'
SEVERITIES=['low', 'medium', 'high', 'severe']; STATES=['proposed', 'assessed', 'design', 'construction', 'accepted', 'rejected']; TRANSITIONS={'proposed': ['assessed'], 'assessed': ['design', 'rejected'], 'design': ['construction'], 'construction': ['accepted'], 'accepted': ['rejected'], 'rejected': []}; TRANSITION_ROLES={'assessed': ['assessor'], 'design': ['structural_engineer'], 'construction': ['structural_engineer'], 'accepted': ['review_board'], 'rejected': ['review_board']}
CREATE_ROLES=set(['assessor']); RECORD_ROLES=set(['assessor', 'structural_engineer']); AUDIT_ROLES=set(['review_board', 'viewer']); VIEW_ROLES=set(['assessor', 'structural_engineer', 'review_board', 'viewer'])
SEVERITY_WEIGHT={'low': 1.0, 'medium': 3.0, 'high': 6.0, 'severe': 9.0}; DEADLINE_HOURS={'low': 72, 'medium': 24, 'high': 8, 'severe': 4}; TERMINAL_STATES=set(['accepted', 'rejected'])
def priority_score(severity,quantity=0.0,threshold=1.0,open_records=0):
    if severity not in SEVERITY_WEIGHT: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(0,min(10,int(round(SEVERITY_WEIGHT[severity]+min(4.0,ratio*4.0)+min(3.0,float(open_records))))))
def response_deadline_hours(severity,quantity=0.0,threshold=1.0):
    if severity not in DEADLINE_HOURS: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(1,int(DEADLINE_HOURS[severity]/max(1.0,ratio)))
def escalation_required(severity,quantity=0.0,threshold=1.0):
    return severity==SEVERITIES[-1] or (threshold>0 and quantity>=threshold)
def can_transition(current,target): return target in TRANSITIONS.get(current,[])
def validate_transition(current,target):
    if current not in STATES or target not in STATES: raise ValidationError("未知状态")
    if not can_transition(current,target): raise ConflictError(f"不能从{current}转换到{target}")
def completion_blockers(target,open_records): return ["仍有未关闭事项"] if target in TERMINAL_STATES and open_records>0 else []
def role_for_transition(target): return set(TRANSITION_ROLES.get(target,[]))
# ===== 余震预警处置 =====
ALERT_ENTITY='余震预警'; DISPOSITION_ENTITY='预警处置'; BATCH_ENTITY='预警推送批次'
ALERT_LEVELS=list(SEVERITIES); ALERT_KINDS=['alert','release']
ALERT_STATUSES=['active','release_pending','resumed']
DISPOSITION_STATUSES=['paused','resumed','invalidated']
BATCH_STATUSES=['queued','completed','partial','failed']
BATCH_ITEM_STATUSES=['pending','ok','failed']
CONFIRM_SLOTS=2; CONSTRUCTION_STATE='construction'
ALERT_PUSH_ROLES=set(['assessor','structural_engineer'])
ALERT_CONFIRM_ROLES=set(['structural_engineer','review_board'])
RISK_UPDATE_ROLES=set(['assessor','structural_engineer'])
# 风险重算门槛：预警等级越高，分值门槛越低（severe时同楼栋在施项目全部重新暂停）
RECONSIDER_CUTOFF={'low':10,'medium':8,'high':6,'severe':0}
def normalize_alert_level(value):
    if value not in ALERT_LEVELS: raise ValidationError("level不在允许范围内")
    return value
def normalize_alert_kind(value):
    if value not in ALERT_KINDS: raise ValidationError("kind必须是alert或release")
    return value
def is_under_construction(item): return item.get('status')==CONSTRUCTION_STATE
def same_building(item, building):
    building=(building or '').strip()
    return bool(building) and (item.get('building') or '').strip()==building
def initial_pause_required(item, building, alert_level):
    # 预警首发保守处置：同楼栋在施项目一律先暂停
    return is_under_construction(item) and same_building(item, building)
def recalc_pause_required(item, alert_level):
    # 风险参数更新后按新预警重算：等级与风险分值共同决定
    if alert_level not in RECONSIDER_CUTOFF: raise ValidationError("unknown alert level")
    if not is_under_construction(item): return False
    score=priority_score(item['severity'],item.get('quantity',0.0),item.get('threshold',1.0))
    return score>=RECONSIDER_CUTOFF[alert_level]
def can_confirm_release(role, actor, prior_actors):
    return role in ALERT_CONFIRM_ROLES and actor not in prior_actors
def batch_result(item_statuses):
    if not item_statuses: return BATCH_STATUSES[1]
    failed=sum(1 for status in item_statuses if status=='failed')
    if failed==len(item_statuses): return BATCH_STATUSES[3]
    return BATCH_STATUSES[2] if failed else BATCH_STATUSES[1]
