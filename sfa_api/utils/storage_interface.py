"""This file contains method stubs to act as the interface for
storage interactions in the Solar Forecast Arbiter. The 'sfa_api.demo'
module is a static implementation intended for developing against when
it is not feasible to utilize a mysql instance or other persistent
storage.
"""
from contextlib import contextmanager
from functools import partial
import random
import uuid


from flask import g, current_app
import pandas as pd
import pymysql
from pymysql import converters


from sfa_api.auth import current_user
from sfa_api import schema
from sfa_api.utils.errors import StorageAuthError, DeleteRestrictionError


# min and max timestamps storable in mysql
MINTIMESTAMP = pd.Timestamp('19700101T000001Z')
MAXTIMESTAMP = pd.Timestamp('20380119T031407Z')


def generate_uuid():
    """Generate a version 1 UUID and ensure clock_seq is random"""
    return str(uuid.uuid1(clock_seq=random.SystemRandom().getrandbits(14)))


def mysql_connection():
    if 'mysql_connection' not in g:
        config = current_app.config
        conv = converters.conversions.copy()
        # either convert decimals to floats, or add decimals to schema
        conv[converters.FIELD_TYPE.DECIMAL] = float
        conv[converters.FIELD_TYPE.NEWDECIMAL] = float
        conv[pd.Timestamp] = converters.escape_datetime
        connect_kwargs = {
            'host': config['MYSQL_HOST'],
            'port': int(config['MYSQL_PORT']),
            'user': config['MYSQL_USER'],
            'password': config['MYSQL_PASSWORD'],
            'database': config['MYSQL_DATABASE'],
            'binary_prefix': True,
            'conv': conv,
            'use_unicode': True,
            'charset': 'utf8mb4',
            'init_command': "SET time_zone = '+00:00'"
        }
        connection = pymysql.connect(**connect_kwargs)
        g.mysql_connection = connection
    return g.mysql_connection


@contextmanager
def get_cursor(cursor_type):
    if cursor_type == 'standard':
        cursorclass = pymysql.cursors.Cursor
    elif cursor_type == 'dict':
        cursorclass = pymysql.cursors.DictCursor
    else:
        raise AttributeError('cursor_type must be standard or dict')
    connection = mysql_connection()
    cursor = connection.cursor(cursor=cursorclass)
    yield cursor
    connection.commit()
    cursor.close()


def try_query(query_cmd):
    try:
        query_cmd()
    except (pymysql.err.OperationalError, pymysql.err.IntegrityError) as e:
        ecode = e.args[0]
        if ecode == 1142 or ecode == 1143:
            raise StorageAuthError(e.args[1])
        elif ecode == 1451:
            raise DeleteRestrictionError
        else:
            raise


def _call_procedure(procedure_name, *args, cursor_type='dict'):
    """
    Can't user callproc since it doesn't properly use converters.
    Will not handle OUT or INOUT parameters without first setting
    local variables and retrieving from those variables
    """
    with get_cursor(cursor_type) as cursor:
        query = f'CALL {procedure_name}({",".join(["%s"] * (len(args) + 1))})'
        query_cmd = partial(cursor.execute, query, (current_user, *args))
        try_query(query_cmd)
        return cursor.fetchall()


def _set_modeling_parameters(site_dict):
    out = {}
    modeling_parameters = {}
    for key in schema.ModelingParameters().fields.keys():
        modeling_parameters[key] = site_dict[key]
    for key in schema.SiteResponseSchema().fields.keys():
        if key == 'modeling_parameters':
            out[key] = modeling_parameters
        else:
            out[key] = site_dict[key]
    return out


def _set_observation_parameters(observation_dict):
    out = {}
    for key in schema.ObservationSchema().fields.keys():
        if key in ('_links',):
            continue
        out[key] = observation_dict[key]
    return out


def _set_forecast_parameters(forecast_dict):
    out = {}
    for key in schema.ForecastSchema().fields.keys():
        if key in ('_links', ):
            continue
        out[key] = forecast_dict[key]
    return out


def store_observation_values(observation_id, observation_df):
    """Store observation data.

    Parameters
    ----------
    observation_id: string
        UUID of the associated observation.
    observation_df: DataFrame
        Dataframe with DatetimeIndex, value, and quality_flag column.

    Returns
    -------
    string
        The UUID of the associated Observation.

    Raises
    ------
    StorageAuthError
        If the user does not have permission to store values on the Observation
        or if the Observation does not exists
    """
    with get_cursor('standard') as cursor:
        query = 'CALL store_observation_values(%s, %s, %s, %s, %s)'
        query_cmd = partial(
            cursor.executemany, query,
            ((current_user, observation_id, row.Index, row.value,
              row.quality_flag)
             for row in observation_df.itertuples()))
        try_query(query_cmd)
    return observation_id


def read_observation_values(observation_id, start=None, end=None):
    """Read observation values between start and end.

    Parameters
    ----------
    observation_id: string
        UUID of associated observation.
    start: datetime
        Beginning of the period for which to request data.
    end: datetime
        End of the peried for which to request data.

    Returns
    -------
    list
        A list of dictionaries representing data points.
        Data points contain a timestamp, value andquality_flag.
        Returns None if the Observation does not exist.
    """
    if start is None:
        start = MINTIMESTAMP
    if end is None:
        end = MAXTIMESTAMP

    obs_vals = _call_procedure('read_observation_values', observation_id,
                               start, end, cursor_type='standard')
    df = pd.DataFrame.from_records(
        list(obs_vals), columns=['observation_id', 'timestamp',
                                 'value', 'quality_flag']
        ).drop(columns='observation_id').set_index(
            'timestamp').tz_localize('UTC')
    return df


def store_observation(observation):
    """Store Observation metadata. Should generate and store a uuid
    as the 'observation_id' field.

    Parameters
    ----------
    observation: dictionary
        A dictionary of observation fields to insert.

    Returns
    -------
    string
        The UUID of the newly created Observation.
    """
    observation_id = generate_uuid()
    # the procedure expects arguments in a certain order
    _call_procedure(
        'store_observation', observation_id,
        observation['variable'], observation['site_id'],
        observation['name'], observation['interval_label'],
        observation['interval_length'], observation['interval_value_type'],
        observation['uncertainty'], observation['extra_parameters'])
    return observation_id


def read_observation(observation_id):
    """Read Observation metadata.

    Parameters
    ----------
    observation_id: String
        UUID of the observation to retrieve.

    Returns
    -------
    dict
        The Observation's metadata or None if the Observation
        does not exist.
    """
    observation = _set_observation_parameters(
        _call_procedure('read_observation', observation_id)[0])
    return observation


def delete_observation(observation_id):
    """Remove an Observation from storage.

    Parameters
    ----------
    observation_id: String
        UUID of observation to delete

    Raises
    ------
    StorageAuthError
        If the user does not have permission to delete the observation
    """
    _call_procedure('delete_observation', observation_id)


def list_observations(site_id=None):
    """Lists all observations a user has access to.

    Parameters
    ----------
    site_id: string
        UUID of Site, when supplied returns only Observations
        made for this Site.

    Returns
    -------
    list
        List of dictionaries of Observation metadata.

    Raises
    ------
    StorageAuthError
        If the user does not have access to observations with site_id or
        no observations exists for that id
    """
    if site_id is not None:
        read_site(site_id)
    observations = [_set_observation_parameters(obs)
                    for obs in _call_procedure('list_observations')
                    if site_id is None or obs['site_id'] == site_id]
    return observations


# Forecasts
def store_forecast_values(forecast_id, forecast_df):
    """Store Forecast data

    Parameters
    ----------
    forecast_id: string
        UUID of the associated forecast.
    forecast_df: DataFrame
        Dataframe with DatetimeIndex and value column.

    Returns
    -------
    string
        The UUID of the associated forecast.

    Raises
    ------
    StorageAuthError
        If the user does not have permission to write values for the Forecast
    """
    with get_cursor('standard') as cursor:
        query = 'CALL store_forecast_values(%s, %s, %s, %s)'
        query_cmd = partial(
            cursor.executemany, query,
            ((current_user, forecast_id, row.Index, row.value)
             for row in forecast_df.itertuples()))
        try_query(query_cmd)
    return forecast_id


def read_forecast_values(forecast_id, start=None, end=None):
    """Read forecast values between start and end.

    Parameters
    ----------
    forecast_id: string
        UUID of associated forecast.
    start: datetime
        Beginning of the period for which to request data.
    end: datetime
        End of the peried for which to request data.

    Returns
    -------
    list
        A list of dictionaries representing data points.
        Data points contain a timestamp and value. Returns
        None if the Forecast does not exist.
    """
    if start is None:
        start = MINTIMESTAMP
    if end is None:
        end = MAXTIMESTAMP

    fx_vals = _call_procedure('read_forecast_values', forecast_id,
                              start, end, cursor_type='standard')
    df = pd.DataFrame.from_records(
        list(fx_vals), columns=['forecast_id', 'timestamp', 'value']
        ).drop(columns='forecast_id').set_index(
            'timestamp').tz_localize('UTC')
    return df


def store_forecast(forecast):
    """Store Forecast metadata. Should generate and store a uuid
    as the 'forecast_id' field.

    Parameters
    ----------
    forecast: dictionary
        A dictionary of forecast fields to insert.

    Returns
    -------
    string
        The UUID of the newly created Forecast.

    Raises
    ------
    StorageAuthError
        If the user can create Forecasts or the user can't read the site
    """
    forecast_id = generate_uuid()
    # the procedure expects arguments in a certain order
    _call_procedure(
        'store_forecast', forecast_id, forecast['site_id'], forecast['name'],
        forecast['variable'], forecast['issue_time_of_day'],
        forecast['lead_time_to_start'], forecast['interval_label'],
        forecast['interval_length'], forecast['run_length'],
        forecast['interval_value_type'], forecast['extra_parameters'])
    return forecast_id


def read_forecast(forecast_id):
    """Read Forecast metadata.

    Parameters
    ----------
    forecast_id: String
        UUID of the forecast to retrieve.

    Returns
    -------
    dict
        The Forecast's metadata or None if the Forecast
        does not exist.
    """
    forecast = _set_forecast_parameters(
        _call_procedure('read_forecast', forecast_id)[0])
    return forecast


def delete_forecast(forecast_id):
    """Remove a Forecast from storage.

    Parameters
    ----------
    forecast_id: String
        UUID of the Forecast to delete.

    Raises
    ------
    StorageAuthError
        If the user cannot delete the Forecast
    """
    _call_procedure('delete_forecast', forecast_id)


def list_forecasts(site_id=None):
    """Lists all Forecasts a user has access to.

    Parameters
    ----------
    site_id: string
        UUID of Site, when supplied returns only Forecasts
        made for this Site.

    Returns
    -------
    list
        List of dictionaries of Forecast metadata.
    """
    if site_id is not None:
        read_site(site_id)
    forecasts = [_set_forecast_parameters(fx)
                 for fx in _call_procedure('list_forecasts')
                 if site_id is None or fx['site_id'] == site_id]
    return forecasts


def read_site(site_id):
    """Read Site metadata.

    Parameters
    ----------
    site_id: String
        UUID of the site to retrieve.

    Returns
    -------
    dict
        The Site's metadata

    Raises
    ------
    StorageAuthError
        If the user does not have access to the site_id or it doesn't exist
    """
    site = _set_modeling_parameters(
        _call_procedure('read_site', site_id)[0])
    return site


def store_site(site):
    """Store Site metadata. Should generate and store a uuid
    as the 'site_id' field.

    Parameters
    ----------
    site: dict
        Dictionary of site data.

    Returns
    -------
    string
        UUID of the newly created site.
    Raises
    ------
    StorageAuthError
        If the user does not have create permissions
    """
    site_id = generate_uuid()
    # the procedure expects arguments in a certain order
    _call_procedure(
        'store_site', site_id, site['name'], site['latitude'],
        site['longitude'], site['elevation'], site['timezone'],
        site['extra_parameters'],
        *[site['modeling_parameters'][key] for key in [
            'ac_capacity', 'dc_capacity', 'temperature_coefficient',
            'tracking_type', 'surface_tilt', 'surface_azimuth',
            'axis_tilt', 'axis_azimuth', 'ground_coverage_ratio',
            'backtrack', 'max_rotation_angle', 'dc_loss_factor',
            'ac_loss_factor']])
    return site_id


def delete_site(site_id):
    """Remove a Site from storage.

    Parameters
    ----------
    site_id: String
        UUID of the Forecast to delete.

    Raises
    ------
    StorageAuthError
        If the user does not have permission to delete the site
    DeleteRestrictionError
        If the site cannote be delete because other objects depend on it
    """
    _call_procedure('delete_site', site_id)


def list_sites():
    """List all sites.

    Returns
    -------
    list
        List of Site metadata as dictionaries.
    """
    sites = [_set_modeling_parameters(site)
             for site in _call_procedure('list_sites')]
    return sites


# CDF Forecasts
def store_cdf_forecast_values(forecast_id, forecast_df):
    """Store CDF Forecast data

    Parameters
    ----------
    forecast_id: string
        UUID of the associated forecast.
    forecast_df: DataFrame
        Dataframe with DatetimeIndex and value column.

    Returns
    -------
    string
        The UUID of the associated forecast. Returns
        None if the CDFForecast does not exist.
    """
    raise NotImplementedError


def read_cdf_forecast_values(forecast_id, start=None, end=None):
    """Read CDF forecast values between start and end.

    Parameters
    ----------
    forecast_id: string
        UUID of associated forecast.
    start: datetime
        Beginning of the period for which to request data.
    end: datetime
        End of the peried for which to request data.

    Returns
    -------
    list
        A list of dictionaries representing data points.
        Data points contain a timestamp and value. Returns
        None if the CDF Forecast does not exist.
    """
    raise NotImplementedError


def store_cdf_forecast(cdf_forecast):
    """Store Forecast metadata. Should generate and store a uuid
    as the 'forecast_id' field.

    Parameters
    ----------
    cdf_forecast: dictionary
        A dictionary of forecast fields to insert.

    Returns
    -------
    string
        The UUID of the newly created CDF Forecast.

    """
    raise NotImplementedError


def read_cdf_forecast(forecast_id):
    """Read CDF Forecast metadata.

    Parameters
    ----------
    forecast_id: String
        UUID of the forecast to retrieve.

    Returns
    -------
    dict
        The CDF Forecast's metadata or None if the Forecast
        does not exist.
    """
    raise NotImplementedError


def delete_cdf_forecast(forecast_id):
    """Remove a CDF Forecast from storage.

    Parameters
    ----------
    forecast_id: String
        UUID of the Forecast to delete.

    Returns
    -------
    dict
        The CDF Forecast's metadata if successful or None
        if the CDF Forecast does not exist.
    """
    raise NotImplementedError


def list_cdf_forecasts(parent_forecast_id=None):
    """Lists all Forecasts a user has access to.

    Parameters
    ----------
    parent_forecast_id: string
        UUID of the parent CDF Forecast Group.

    Returns
    -------
    list
        List of dictionaries of CDF Forecast metadata.
    """
    raise NotImplementedError


# CDF Probability Groups
def store_cdf_forecast_group(cdf_forecast_group):
    """Store CDF Forecast Group metadata. Should generate
    and store a uuid as the 'forecast_id' field.

    Parameters
    ----------
    cdf_forecast_group: dictionary
        A dictionary of CDF Forecast Group fields to insert.

    Returns
    -------
    string
        The UUID of the newly created CDF Forecast.

    """
    raise NotImplementedError


def read_cdf_forecast_group(forecast_id):
    """Read CDF Forecast metadata.

    Parameters
    ----------
    forecast_id: String
        UUID of the forecast to retrieve.

    Returns
    -------
    dict
        The CDF Forecast's metadata or None if the Forecast
        does not exist.
    """
    raise NotImplementedError


def delete_cdf_forecast_group(forecast_id):
    """Remove a CDF Forecast Grpup from storage.

    Parameters
    ----------
    forecast_id: String
        UUID of the CDF Forecast Group to delete.

    Returns
    -------
    dict
        The CDF Forecast Groups's metadata if successful or
        None if the CDF Forecast does not exist.
    """
    raise NotImplementedError


def list_cdf_forecast_groups():
    """Lists all CDF Forecast Groups a user has access to.

    Returns
    -------
    list
        List of dictionaries of CDF Forecast Group metadata.
    """
    raise NotImplementedError
