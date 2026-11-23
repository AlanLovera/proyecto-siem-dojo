"""Consulta literal sin modificar el conjunto importado ni sus referencias."""

import pandas as pd


def filter_records(frame, text="", sources=(), severities=()):
    mask = pd.Series(True, index=frame.index)
    if sources:
        mask &= frame["Log_Source"].isin(sources)
    if severities:
        mask &= frame["Severity"].isin(severities)
    if text:
        matches = frame.map(
            lambda value: text.casefold() in str(value).casefold() if value is not None else False
        )
        mask &= matches.any(axis=1)
    return frame.loc[mask].copy()


def display_records(frame):
    """Arrow necesita un tipo uniforme; solo la copia de presentación usa texto."""
    result = frame.copy()
    for column in result.columns:
        if column != "__dojo_row":
            result[column] = result[column].map(lambda v: None if v is None else str(v))
    return result
