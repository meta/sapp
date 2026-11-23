# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.


from __future__ import annotations

import re
import signal
import threading
from abc import ABC, abstractmethod
from typing import Any, Generic, List, Optional, Pattern, Sequence, Set, TypeVar, Union

from sqlalchemy import Column
from sqlalchemy.orm.query import Query
from sqlalchemy.sql.expression import or_
from typing_extensions import Final

from ..models import DBID
from .query_result import IssueQueryResult

_Q = TypeVar("_Q")
_T = TypeVar("_T")


class Predicate(ABC):
    pass


class QueryPredicate(Predicate):
    @abstractmethod
    def apply(self, query: Query[_Q]) -> Query[_Q]: ...


class InRange(Generic[_T], QueryPredicate):
    def __init__(
        self,
        column: Column[_T],
        *,
        lower: Optional[_T] = None,
        upper: Optional[_T] = None,
    ) -> None:
        self._column = column
        # pyrefly: ignore [unsupported-operation]
        self._lower: Final[Optional[_T]] = lower
        # pyrefly: ignore [unsupported-operation]
        self._upper: Final[Optional[_T]] = upper

    def apply(self, query: Query[_Q]) -> Query[_Q]:
        if self._lower is not None:
            query = query.filter(self._column >= self._lower)
        if self._upper is not None:
            query = query.filter(self._column <= self._upper)
        return query


class Equals(Generic[_T], QueryPredicate):
    def __init__(self, column: Union[Column[_T], DBID], to: _T) -> None:
        self._column = column
        # pyrefly: ignore [unsupported-operation]
        self._to: Final[Optional[_T]] = to

    def apply(self, query: Query[_Q]) -> Query[_Q]:
        return query.filter(self._column == self._to)


class IsNull(Generic[_T], QueryPredicate):
    def __init__(self, column: Union[Column[_T], DBID]) -> None:
        self._column = column

    def apply(self, query: Query[_Q]) -> Query[_Q]:
        return query.filter(self._column is None)


class Like(Generic[_T], QueryPredicate):
    def __init__(self, column: Union[Column[_T], DBID], items: Sequence[_T]) -> None:
        self._column = column
        self._items = items

    def apply(self, query: Query[_Q]) -> Query[_Q]:
        # pyre-ignore: SQLAlchemy too dynamic.
        return query.filter(or_(*[self._column.like(item) for item in self._items]))


class IssuePredicate(Predicate):
    @abstractmethod
    def apply(self, issues: List[IssueQueryResult]) -> List[IssueQueryResult]: ...


class HasAll(IssuePredicate):
    def __init__(self, features: Set[str]) -> None:
        self._features = features

    def apply(self, issues: List[IssueQueryResult]) -> List[IssueQueryResult]:
        return [
            issue
            for issue in issues
            if issue.features & self._features == self._features
        ]


class Matches(IssuePredicate):
    # Mitigations for CWE-1333 (ReDoS): the pattern comes from the GraphQL
    # `matches` filter fields, which are unauthenticated, and Python's `re`
    # has no timeout. Cap the pattern length, and bound the total time spent
    # matching in apply() with SIGALRM when we run on the main thread.
    MAX_REGEX_LENGTH = 512
    APPLY_TIMEOUT_SECONDS = 1.0

    def __init__(self, regex: str, parameter_name: str) -> None:
        if len(regex) > self.MAX_REGEX_LENGTH:
            raise ValueError(
                f"regex for {parameter_name} exceeds the {self.MAX_REGEX_LENGTH} "
                "character limit"
            )
        self._regex: Pattern[str] = re.compile(regex)
        self._parameter_name = parameter_name

    def attribute_set(self, issue: IssueQueryResult) -> Set[str]:
        attribute = issue._asdict()[self._parameter_name]
        if isinstance(attribute, str):
            return {attribute}
        return set(attribute)

    def _on_timeout(self, signum: int, frame: Any) -> None:
        raise TimeoutError("regex match timed out")

    def _apply(self, issues: List[IssueQueryResult]) -> List[IssueQueryResult]:
        return [
            issue
            for issue in issues
            if any(map(self._regex.match, self.attribute_set(issue)))
        ]

    def apply(self, issues: List[IssueQueryResult]) -> List[IssueQueryResult]:
        if hasattr(signal, "setitimer") and (
            threading.current_thread() is threading.main_thread()
        ):
            previous_handler = signal.signal(signal.SIGALRM, self._on_timeout)
            signal.setitimer(signal.ITIMER_REAL, self.APPLY_TIMEOUT_SECONDS)
            try:
                return self._apply(issues)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous_handler)
        return self._apply(issues)


class HasAny(IssuePredicate):
    def __init__(self, parameter_list: Set[str], parameter_name: str) -> None:
        self._parameter_list = parameter_list
        self._parameter_name = parameter_name

    def attribute_set(self, issue: IssueQueryResult) -> Set[str]:
        attribute = issue._asdict()[self._parameter_name]
        if isinstance(attribute, str):
            return {attribute}
        return set(attribute)

    def apply(self, issues: List[IssueQueryResult]) -> List[IssueQueryResult]:
        return [
            issue
            for issue in issues
            if not self.attribute_set(issue).isdisjoint(self._parameter_list)
        ]


class HasNone(IssuePredicate):
    def __init__(self, features: Set[str]) -> None:
        self._features = features

    def apply(self, issues: List[IssueQueryResult]) -> List[IssueQueryResult]:
        return [issue for issue in issues if len(issue.features & self._features) == 0]
