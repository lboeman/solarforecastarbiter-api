from flask import Blueprint, jsonify
from flask.views import MethodView

from sfa_api.schema import UserSchema, InviteSchema
from sfa_api.utils.storage import get_storage


class UserInviteView(MethodView):
    def get(self):
        """
        ---
        summary: List any pending invites for the current user.
        description: List any pending invites for the current user.
        tags:
          - invites
        response:
          200:
            description: A list of organization invitations
            content:
              application/json:
                schema:
                  type: array
                  items:
                    $ref: '#/components/schemas/InviteSchema'
          401:
            $ref: '#/components/responses/401-Unauthorized'
        """
        storage = get_storage()
        invites = storage.list_user_invites()
        return jsonify(InviteSchema(many=True).dump(invites)), 200


class SingleInviteView(MethodView):
    def post(self, invite_id):
        """
        ---
        description: Accept an invititation to an organization.
        tags:
          - invites
        responses:
          204:
            description: Successfully accepted invitation.
          401:
            $ref: '#/components/responses/401-Unauthorized'
          404:
            $ref: '#/components/responses/404-NotFound'
        """
        storage = get_storage()
        storage.accept_invitation(invite_id)
        return '', 204
        


class InviteView(MethodView):
    def post(self, auth0id):
        """
        ---
        description: Invite a user to your organization by Auth0 id.
        tags:
          - invites
        responses:
          204:
            description: Invite created successfully.
          401:
            $ref: '#/components/responses/401-Unauthorized'
          404:
            $ref: '#/components/responses/404-NotFound'
        """
        storage = get_storage()
        storage.invite_user_to_organization(auth0id)
        return '', 204


invite_blp = Blueprint(
    'invites', 'invites', url_prefix='/invites',
)
invite_blp.add_url_rule('/', view_func=UserInviteView.as_view('all'))
invite_blp.add_url_rule('/accept/<invite_id>', view_func=SingleInviteView.as_view('accept'))
invite_blp.add_url_rule('/invite/<auth0id>', view_func=InviteView.as_view('invite_user'))
