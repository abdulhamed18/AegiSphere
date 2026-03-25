"""
Phase 3 – URL routing for join governance API.
Namespace: api/workspaces/
"""

from django.urls import path

from . import join_governance_views as views

app_name = "workspaces_api"

urlpatterns = [
    path("join/", views.SubmitJoinRequestView.as_view(), name="join-submit"),
    path("join-requests/", views.ListJoinRequestsView.as_view(), name="join-requests-list"),
    path("join/<int:id>/withdraw/", views.WithdrawJoinRequestView.as_view(), name="join-withdraw"),
    path("join/<int:id>/approve/", views.ApproveJoinRequestView.as_view(), name="join-approve"),
    path("join/<int:id>/reject/", views.RejectJoinRequestView.as_view(), name="join-reject"),
    path("invite/", views.CreateInviteView.as_view(), name="invite-create"),
    path("invites/", views.ListInvitesView.as_view(), name="invites-list"),
    path("invite/accept/", views.AcceptInviteView.as_view(), name="invite-accept"),
    path("block/", views.BlockUserView.as_view(), name="block-user"),
    path("unblock/", views.UnblockUserView.as_view(), name="unblock-user"),
    path("block-list/", views.ListBlockListView.as_view(), name="block-list"),
    path("members/", views.ListMembersView.as_view(), name="members-list"),
    path("members/<int:id>/change-role/", views.ChangeMemberRoleView.as_view(), name="member-change-role"),
    path("leave/", views.LeaveWorkspaceView.as_view(), name="leave-workspace"),
]
