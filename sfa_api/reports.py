from flask import (
    Blueprint, request, jsonify, make_response, url_for, current_app)
from flask.views import MethodView
from marshmallow import ValidationError
from solarforecastarbiter.io.utils import HiddenToken
from solarforecastarbiter.reports.main import compute_report


from sfa_api import spec
from sfa_api.utils.auth import current_access_token
from sfa_api.utils.errors import BadAPIRequest, StorageAuthError
from sfa_api.utils.queuing import get_queue
from sfa_api.utils.storage import get_storage
from sfa_api.schema import (ReportPostSchema, ReportValuesPostSchema,
                            ReportSchema, SingleReportSchema,
                            RawReportSchema)


REPORT_STATUS_OPTIONS = ['pending', 'failed', 'complete']


def enqueue_report(report_id, base_url):
    alt_base_url = current_app.config.get('JOB_BASE_URL')
    if alt_base_url is not None:
        base_url = alt_base_url
    q = get_queue('reports')
    q.enqueue(
        compute_report,
        HiddenToken(current_access_token),
        report_id,
        base_url=base_url,
        result_ttl=0,
        job_timeout=current_app.config['REPORT_JOB_TIMEOUT']
    )


class AllReportsView(MethodView):
    def get(self):
        """
        ---
        summary: List Reports.
        tags:
          - Reports
        responses:
          200:
            description: A List of reports
            content:
              application/json:
                schema:
                  type: array
                  items:
                    $ref: '#/components/schemas/ReportSchema'
          401:
            $ref: '#/components/responses/401-Unauthorized'
        """
        storage = get_storage()
        reports = storage.list_reports()
        return jsonify(ReportSchema(many=True).dump(reports))

    def post(self):
        """
        ---
        summary: Create a new report.
        tags:
          - Reports
        requestBody:
          description: Metadata of the report to create.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ReportMetadata'
        responses:
          201:
            description: Report created successfully.
            content:
              application/json:
                schema:
                  type: string
                  format: uuid
                  description: The uuid of the created report.
            headers:
              Location:
                schema:
                  type: string
                  format: uri
                  description: Url of the created report.
          400:
            $ref: '#/components/responses/400-BadRequest'
          401:
            $ref: '#/components/responses/401-Unauthorized'
          404:
            $ref: '#/components/responses/404-NotFound'
        """
        data = request.get_json()
        try:
            report = ReportPostSchema().load(data)
        except ValidationError as err:
            raise BadAPIRequest(err.messages)
        storage = get_storage()
        report_id = storage.store_report(report)
        response = make_response(report_id, 201)
        response.headers['Location'] = url_for('reports.single',
                                               report_id=report_id)
        enqueue_report(report_id, request.url_root.rstrip('/'))
        return response


class RecomputeReportView(MethodView):
    def get(self, report_id):
        """
        ---
        summary: Recompute a report.
        tags:
          - Reports
        parameters:
        - report_id
        responses:
          200:
            description: Sucessfully scheduled report computation.
            content:
              application/json:
                schema:
                  type: string
                  format: uuid
                  description: The uuid of the report
            headers:
              Location:
                schema:
                  type: string
                  format: uri
                  description: Url of the report.
          401:
            $ref: '#/components/responses/401-Unauthorized'
          404:
            $ref: '#components/responses/404-NotFound'
        """
        storage = get_storage()
        report_perms = storage.get_user_actions_on_object(report_id)
        if 'update' not in report_perms:
            raise StorageAuthError()
        enqueue_report(report_id, request.url_root.rstrip('/'))
        response = make_response(report_id, 200)
        response.headers['Location'] = url_for('reports.single',
                                               report_id=report_id)
        return response


class ReportView(MethodView):
    def get(self, report_id):
        """
        ---
        summary: Get report metadata.
        tags:
          - Reports
        parameters:
        - report_id
        responses:
          200:
            description: Successfully retrieved report metadata.
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/SingleReportSchema'
          401:
            $ref: '#/components/responses/401-Unauthorized'
          404:
            $ref: '#components/responses/404-NotFound'
        """
        storage = get_storage()
        report = storage.read_report(report_id)
        return jsonify(SingleReportSchema().dump(report))

    def delete(self, report_id):
        """
        ---
        summary: Delete a report.
        tags:
          - Reports
        parameters:
        - report_id
        responses:
          204:
            description: Deleted report successfully.
          401:
            $ref: '#/components/responses/401-Unauthorized'
          404:
            $ref: '#components/responses/404-NotFound'
        """
        storage = get_storage()
        storage.delete_report(report_id)
        return '', 204


class ReportStatusView(MethodView):
    def post(self, report_id, status):
        """
        ---
        summary: Update the report status
        tags:
          - Reports
        parameters:
          - report_id
          - status
        responses:
          204:
            description: Updated status successfully.
          401:
            $ref: '#/components/responses/401-Unauthorized'
          404:
            $ref: '#components/responses/404-NotFound'
        """
        if status not in REPORT_STATUS_OPTIONS:
            raise BadAPIRequest(
                {'status': 'Must be one of '
                           '{",".join(REPORT_STATUS_OPTIONS)}.'})
        storage = get_storage()
        storage.store_report_status(report_id, status)
        return '', 204


class RawReportView(MethodView):
    def post(self, report_id):
        """
        ---
        summary: Store Raw Report
        tags:
          - Reports
        requestBody:
          description: JSON object containing the raw report.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RawReportSchema'
        parameters:
          - report_id
        """
        raw_report_dict = request.get_json()
        raw_report = RawReportSchema().load(raw_report_dict)
        storage = get_storage()
        storage.store_raw_report(report_id, raw_report)
        return '', 204


class ReportValuesView(MethodView):
    def get(self, report_id):
        """
        ---
        summary: Get the processed values used in a report
        tags:
        - Reports
        parameters:
        - report_id
        responses:
          200:
            description: Successfully retrieved
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/ReportValuesSchema'
          404:
            $ref: '#/components/responses/404-NotFound'
        """
        storage = get_storage()
        values = storage.read_report_values(report_id)
        return jsonify(values)

    def post(self, report_id):
        """
        ---
        summary: Store processed values used in the report.
        tags:
        - Reports
        parameters:
        - report_id
        requestBody:
          description: >-
            JSON object mapping uuids to processed data used in report
            generation.
          required: True
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ReportValuesPostSchema'
        responses:
          201:
            description: UUID of the stored values.
          400:
            $ref: '#/components/responses/400-BadRequest'
          404:
            $ref: '#/components/responses/404-NotFound'
        """
        # while developing, just read data as string and then
        # storage will convert to bytes for the blob column
        raw_values = request.get_json()
        try:
            report_values = ReportValuesPostSchema().load(raw_values)
        except ValidationError as err:
            raise BadAPIRequest(err.messages)
        storage = get_storage()
        value_id = storage.store_report_values(
            report_id,
            report_values['object_id'],
            report_values['processed_values']
        )
        return value_id, 201


spec.components.parameter(
    'report_id', 'path',
    {
        'schema': {
            'type': 'string',
            'format': 'uuid'
        },
        'description': "The report's unique identifier",
        'required': 'true',
        'name': 'report_id'
    })
spec.components.parameter(
    'status', 'path',
    {
        'schema': {
            'type': 'string',
        },
        'description': "The new status of the report",
        'required': 'true',
        'name': 'status'
    })

reports_blp = Blueprint(
    'reports', 'reports', url_prefix='/reports',
)
reports_blp.add_url_rule(
    '/',
    view_func=AllReportsView.as_view('all')
)
reports_blp.add_url_rule(
    '/<uuid_str:report_id>',
    view_func=ReportView.as_view('single')
)
reports_blp.add_url_rule(
    '/<uuid_str:report_id>/status/<status>',
    view_func=ReportStatusView.as_view('status')
)
reports_blp.add_url_rule(
    '/<uuid_str:report_id>/raw',
    view_func=RawReportView.as_view('metrics')
)
reports_blp.add_url_rule(
    '/<uuid_str:report_id>/values',
    view_func=ReportValuesView.as_view('values')
)
reports_blp.add_url_rule(
    '/<uuid_str:report_id>/recompute',
    view_func=RecomputeReportView.as_view('recompute')
)
