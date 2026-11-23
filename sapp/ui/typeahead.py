# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.


from __future__ import annotations

from typing import List

import graphene  # @manual=fbsource//third-party/pypi/graphene-legacy:graphene-legacy
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Issue, IssueInstance, SharedText, SharedTextKind

# Typeahead lists are for autocompletion; cap the rows each resolver reads so
# one GraphQL query cannot materialize an entire table (CWE-400).
TYPEAHEAD_LIMIT = 10_000


class Code(graphene.ObjectType):
    code = graphene.Int()


def all_codes(session: Session) -> List[Code]:
    return (
        session.execute(
            select(Issue.code.distinct().label("code")).limit(TYPEAHEAD_LIMIT)
        )
        .scalars()
        .all()
    )


class Path(graphene.ObjectType):
    path = graphene.String()


def all_paths(session: Session) -> List[Path]:
    return session.execute(
        select(IssueInstance, SharedText.contents.label("path"))
        .join(SharedText, SharedText.id == IssueInstance.filename_id)
        .group_by(SharedText)
        .limit(TYPEAHEAD_LIMIT)
    ).all()


class SourceName(graphene.ObjectType):
    source_name = graphene.String()


def all_source_names(session: Session) -> List[SourceName]:
    return session.execute(
        select(IssueInstance, SharedText.contents.label("source_name"))
        .join(SharedText, SharedText.kind == SharedTextKind.source_detail)
        .group_by(SharedText)
        .limit(TYPEAHEAD_LIMIT)
    ).all()


class SourceKind(graphene.ObjectType):
    source_kind = graphene.String()


def all_source_kinds(session: Session) -> List[SourceName]:
    return session.execute(
        select(IssueInstance, SharedText.contents.label("source_kind"))
        .join(SharedText, SharedText.kind == SharedTextKind.source)
        .group_by(SharedText)
        .limit(TYPEAHEAD_LIMIT)
    ).all()


class SinkName(graphene.ObjectType):
    sink_name = graphene.String()


def all_sink_names(session: Session) -> List[SourceName]:
    return session.execute(
        select(IssueInstance, SharedText.contents.label("sink_name"))
        .join(SharedText, SharedText.kind == SharedTextKind.sink_detail)
        .group_by(SharedText)
        .limit(TYPEAHEAD_LIMIT)
    ).all()


class SinkKind(graphene.ObjectType):
    sink_kind = graphene.String()


def all_sink_kinds(session: Session) -> List[SourceName]:
    return session.execute(
        select(IssueInstance, SharedText.contents.label("sink_kind"))
        .join(SharedText, SharedText.kind == SharedTextKind.sink)
        .group_by(SharedText)
        .limit(TYPEAHEAD_LIMIT)
    ).all()


class Status(graphene.ObjectType):
    status = graphene.String()


def all_statuses(session: Session) -> List[Status]:
    return (
        session.execute(
            select(Issue.status.distinct().label("status")).limit(TYPEAHEAD_LIMIT)
        )
        .scalars()
        .all()
    )


class Callable(graphene.ObjectType):
    callable = graphene.String()


def all_callables(session: Session) -> List[Callable]:
    return session.execute(
        select(IssueInstance, SharedText.contents.label("callable"))
        .join(SharedText, SharedText.id == IssueInstance.callable_id)
        .group_by(SharedText)
        .limit(TYPEAHEAD_LIMIT)
    ).all()


class Feature(graphene.ObjectType):
    feature = graphene.String()


def all_features(session: Session) -> List[Feature]:
    return session.execute(
        select(SharedText, SharedText.contents.label("feature"))
        .filter(SharedText.kind == SharedTextKind.feature)
        .limit(TYPEAHEAD_LIMIT)
    ).all()
