import os

import pytest

from sfa_api import create_app
from sfa_api.schema import VARIABLES, INTERVAL_VALUE_TYPES, INTERVAL_LABELS


BASE_URL = 'https://localhost'

# Strings of formatted field options for error checking
# e.g. provides "interval_mean, instantaneous, ..." so
# f'Must be one of: {interval_value_types}.' can be checked
# against the errors returned from marshmallow
variables = ', '.join(VARIABLES)
interval_value_types = ', '.join(INTERVAL_VALUE_TYPES)
interval_labels = ', '.join(INTERVAL_LABELS)


VALID_SITE_JSON = {
    "elevation": 500.0,
    "extra_parameters": '{"parameter": "value"}',
    "latitude": 42.19,
    "longitude": -122.7,
    "modeling_parameters": {
        "ac_capacity": 0.015,
        "dc_capacity": 0.015,
        "backtrack": True,
        "temperature_coefficient": -.002,
        "ground_coverage_ratio": 0.5,
        "surface_azimuth": 180,
        "surface_tilt": 45.0,
        "tracking_type": "fixed"
    },
    "name": "Test Site",
    "timezone": "Etc/GMT+8",
}

VALID_FORECAST_JSON = {
    "extra_parameters": '{"instrument": "pyranometer"}',
    "name": "test forecast",
    "site_id": "123e4567-e89b-12d3-a456-426655440001",
    "variable": "ac_power",
    "interval_label": "beginning",
    "issue_time_of_day": "12:00",
    "lead_time_to_start": 60,
    "interval_length": 1,
    "run_length": 1440,
    "interval_value_type": "interval_mean",
}


VALID_OBS_JSON = {
    "extra_parameters": '{"instrument": "Ascension Technology Rotating Shadowband Pyranometer"}', # NOQA
    "name": "Ashland OR, ghi",
    "site_id": "123e4567-e89b-12d3-a456-426655440001",
    "variable": "ghi",
    "interval_label": "beginning",
    "interval_length": 1,
}


VALID_CDF_FORECAST_JSON = VALID_FORECAST_JSON.copy()
VALID_CDF_FORECAST_JSON.update({
    "name": 'test cdf forecast',
    "axis": 'x',
    "constant_values": [5.0, 20.0, 50.0, 80.0, 95.0]
})


def copy_update(json, key, value):
    new_json = json.copy()
    new_json[key] = value
    return new_json


@pytest.fixture(scope="module")
def app():
    if not os.getenv('SFA_API_STATIC_DATA'):
        os.environ['SFA_API_STATIC_DATA'] = 'true'
    app = create_app(config_name='TestingConfig')
    return app


@pytest.fixture()
def api(app, mocker):
    verify = mocker.patch('sfa_api.utils.auth.verify_access_token')
    verify.return_value = True
    api = app.test_client()
    return api


@pytest.fixture()
def missing_id():
    return '7d2c3208-5243-11e9-8647-d663bd873d93'


@pytest.fixture()
def observation_id():
    return '123e4567-e89b-12d3-a456-426655440000'


@pytest.fixture()
def cdf_forecast_group_id():
    return 'ef51e87c-50b9-11e9-8647-d663bd873d93'


@pytest.fixture()
def cdf_forecast_id():
    return '633f9396-50bb-11e9-8647-d663bd873d93'


@pytest.fixture()
def forecast_id():
    return 'f8dd49fa-23e2-48a0-862b-ba0af6dec276'


@pytest.fixture()
def site_id():
    return 'd2018f1d-82b1-422a-8ec4-4e8b3fe92a4a'


@pytest.fixture()
def site_id_plant():
    return '123e4567-e89b-12d3-a456-426655440002'
