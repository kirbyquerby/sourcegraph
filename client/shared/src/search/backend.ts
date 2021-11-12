import { Observable, of } from 'rxjs'
import { map } from 'rxjs/operators'

import { dataOrThrowErrors, gql } from '@sourcegraph/shared/src/graphql/graphql'
import * as GQL from '@sourcegraph/shared/src/graphql/schema'
import { createAggregateError } from '@sourcegraph/shared/src/util/errors'
import { memoizeObservable } from '@sourcegraph/shared/src/util/memoizeObservable'

import { AuthenticatedUser } from '../auth'
import {
    EventLogsDataResult,
    EventLogsDataVariables,
    CreateSavedSearchResult,
    CreateSavedSearchVariables,
    DeleteSavedSearchResult,
    DeleteSavedSearchVariables,
    UpdateSavedSearchResult,
    UpdateSavedSearchVariables,
    ListSearchContextsResult,
    ListSearchContextsVariables,
    AutoDefinedSearchContextsResult,
    AutoDefinedSearchContextsVariables,
    IsSearchContextAvailableResult,
    IsSearchContextAvailableVariables,
    Scalars,
    FetchSearchContextResult,
    FetchSearchContextVariables,
    CreateSearchContextResult,
    CreateSearchContextVariables,
    UpdateSearchContextVariables,
    UpdateSearchContextResult,
    DeleteSearchContextVariables,
    DeleteSearchContextResult,
    Maybe,
    FetchSearchContextBySpecResult,
    FetchSearchContextBySpecVariables,
    highlightCodeResult,
    highlightCodeVariables,
    SavedSearchResult,
    SavedSearchVariables,
    savedSearchesResult,
    savedSearchesVariables,
    SavedSearchFields,
    ReposByQueryResult,
    ReposByQueryVariables,
} from '../graphql-operations'
import { PlatformContext } from '../platform/context'

const searchContextFragment = gql`
    fragment SearchContextFields on SearchContext {
        __typename
        id
        name
        namespace {
            __typename
            id
            namespaceName
        }
        spec
        description
        public
        autoDefined
        updatedAt
        viewerCanManage
        repositories {
            __typename
            repository {
                name
            }
            revisions
        }
    }
`

export function fetchAutoDefinedSearchContexts(
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<AutoDefinedSearchContextsResult['autoDefinedSearchContexts']> {
    return platformContext
        .requestGraphQL<AutoDefinedSearchContextsResult, AutoDefinedSearchContextsVariables>({
            request: gql`
                query AutoDefinedSearchContexts {
                    autoDefinedSearchContexts {
                        ...SearchContextFields
                    }
                }
                ${searchContextFragment}
            `,
            variables: {},
            mightContainPrivateInfo: false,
        })
        .pipe(
            map(dataOrThrowErrors),
            map(({ autoDefinedSearchContexts }) => autoDefinedSearchContexts as GQL.ISearchContext[])
        )
}

export function getUserSearchContextNamespaces(
    authenticatedUser: Pick<AuthenticatedUser, 'id' | 'organizations'> | null
): Maybe<Scalars['ID']>[] {
    return authenticatedUser
        ? [null, authenticatedUser.id, ...authenticatedUser.organizations.nodes.map(org => org.id)]
        : [null]
}

export function fetchSearchContexts({
    first,
    namespaces,
    query,
    after,
    orderBy,
    descending,
    platformContext,
}: {
    first: number
    query?: string
    namespaces?: Maybe<Scalars['ID']>[]
    after?: string
    orderBy?: GQL.SearchContextsOrderBy
    descending?: boolean
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
}): Observable<ListSearchContextsResult['searchContexts']> {
    return platformContext
        .requestGraphQL<ListSearchContextsResult, ListSearchContextsVariables>({
            request: gql`
                query ListSearchContexts(
                    $first: Int!
                    $after: String
                    $query: String
                    $namespaces: [ID]
                    $orderBy: SearchContextsOrderBy
                    $descending: Boolean
                ) {
                    searchContexts(
                        first: $first
                        after: $after
                        query: $query
                        namespaces: $namespaces
                        orderBy: $orderBy
                        descending: $descending
                    ) {
                        nodes {
                            ...SearchContextFields
                        }
                        pageInfo {
                            hasNextPage
                            endCursor
                        }
                        totalCount
                    }
                }
                ${searchContextFragment}
            `,
            variables: {
                first,
                after: after ?? null,
                query: query ?? null,
                namespaces: namespaces ?? [],
                orderBy: orderBy ?? GQL.SearchContextsOrderBy.SEARCH_CONTEXT_SPEC,
                descending: descending ?? false,
            },
            mightContainPrivateInfo: true,
        })
        .pipe(
            map(dataOrThrowErrors),
            map(data => data.searchContexts)
        )
}

export const fetchSearchContext = (
    id: Scalars['ID'],
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<GQL.ISearchContext> => {
    const query = gql`
        query FetchSearchContext($id: ID!) {
            node(id: $id) {
                ... on SearchContext {
                    ...SearchContextFields
                }
            }
        }
        ${searchContextFragment}
    `

    return platformContext
        .requestGraphQL<FetchSearchContextResult, FetchSearchContextVariables>({
            request: query,
            variables: {
                id,
            },
            mightContainPrivateInfo: true,
        })
        .pipe(
            map(dataOrThrowErrors),
            map(data => data.node as GQL.ISearchContext)
        )
}

export const fetchSearchContextBySpec = (
    spec: string,
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<GQL.ISearchContext> => {
    const query = gql`
        query FetchSearchContextBySpec($spec: String!) {
            searchContextBySpec(spec: $spec) {
                ...SearchContextFields
            }
        }
        ${searchContextFragment}
    `

    return platformContext
        .requestGraphQL<FetchSearchContextBySpecResult, FetchSearchContextBySpecVariables>({
            request: query,
            variables: {
                spec,
            },
            mightContainPrivateInfo: true,
        })
        .pipe(
            map(dataOrThrowErrors),
            map(data => data.searchContextBySpec as GQL.ISearchContext)
        )
}

export function createSearchContext(
    variables: CreateSearchContextVariables,
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<GQL.ISearchContext> {
    return platformContext
        .requestGraphQL<CreateSearchContextResult, CreateSearchContextVariables>({
            request: gql`
                mutation CreateSearchContext(
                    $searchContext: SearchContextInput!
                    $repositories: [SearchContextRepositoryRevisionsInput!]!
                ) {
                    createSearchContext(searchContext: $searchContext, repositories: $repositories) {
                        ...SearchContextFields
                    }
                }
                ${searchContextFragment}
            `,
            variables,
            mightContainPrivateInfo: true,
        })
        .pipe(
            map(dataOrThrowErrors),
            map(data => data.createSearchContext as GQL.ISearchContext)
        )
}

export function updateSearchContext(
    variables: UpdateSearchContextVariables,
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<GQL.ISearchContext> {
    return platformContext
        .requestGraphQL<UpdateSearchContextResult, UpdateSearchContextVariables>({
            request: gql`
                mutation UpdateSearchContext(
                    $id: ID!
                    $searchContext: SearchContextEditInput!
                    $repositories: [SearchContextRepositoryRevisionsInput!]!
                ) {
                    updateSearchContext(id: $id, searchContext: $searchContext, repositories: $repositories) {
                        ...SearchContextFields
                    }
                }
                ${searchContextFragment}
            `,
            variables,
            mightContainPrivateInfo: true,
        })
        .pipe(
            map(dataOrThrowErrors),
            map(data => data.updateSearchContext as GQL.ISearchContext)
        )
}

export function deleteSearchContext(
    id: GQL.ID,
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<DeleteSearchContextResult> {
    return platformContext
        .requestGraphQL<DeleteSearchContextResult, DeleteSearchContextVariables>({
            request: gql`
                mutation DeleteSearchContext($id: ID!) {
                    deleteSearchContext(id: $id) {
                        alwaysNil
                    }
                }
            `,
            variables: { id },
            mightContainPrivateInfo: false,
        })
        .pipe(map(dataOrThrowErrors))
}

export function isSearchContextAvailable(
    spec: string,
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<IsSearchContextAvailableResult['isSearchContextAvailable']> {
    return platformContext
        .requestGraphQL<IsSearchContextAvailableResult, IsSearchContextAvailableVariables>({
            request: gql`
                query IsSearchContextAvailable($spec: String!) {
                    isSearchContextAvailable(spec: $spec)
                }
            `,
            variables: { spec },
            mightContainPrivateInfo: true,
        })
        .pipe(map(result => result.data?.isSearchContextAvailable ?? false))
}

export function fetchReposByQuery(
    query: string,
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<{ name: string; url: string }[]> {
    return platformContext
        .requestGraphQL<ReposByQueryResult, ReposByQueryVariables>({
            request: gql`
                query ReposByQuery($query: String!) {
                    search(query: $query) {
                        results {
                            repositories {
                                name
                                url
                            }
                        }
                    }
                }
            `,
            variables: { query },
            mightContainPrivateInfo: true,
        })
        .pipe(
            map(({ data, errors }) => {
                if (!data || !data.search || !data.search.results || !data.search.results.repositories) {
                    throw createAggregateError(errors)
                }
                return data.search.results.repositories
            })
        )
}

const savedSearchFragment = gql`
    fragment SavedSearchFields on SavedSearch {
        id
        description
        notify
        notifySlack
        query
        namespace {
            __typename
            id
            namespaceName
        }
        slackWebhookURL
    }
`

export function fetchSavedSearches(
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<SavedSearchFields[]> {
    return platformContext
        .requestGraphQL<savedSearchesResult, savedSearchesVariables>({
            request: gql`
                query savedSearches {
                    savedSearches {
                        ...SavedSearchFields
                    }
                }
                ${savedSearchFragment}
            `,
            variables: {},
            mightContainPrivateInfo: false,
        })
        .pipe(
            map(({ data, errors }) => {
                if (!data || !data.savedSearches) {
                    throw createAggregateError(errors)
                }
                return data.savedSearches
            })
        )
}

export function fetchSavedSearch(
    id: Scalars['ID'],
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<GQL.ISavedSearch> {
    return platformContext
        .requestGraphQL<SavedSearchResult, SavedSearchVariables>({
            request: gql`
                query SavedSearch($id: ID!) {
                    node(id: $id) {
                        ... on SavedSearch {
                            id
                            description
                            query
                            notify
                            notifySlack
                            slackWebhookURL
                            namespace {
                                id
                            }
                        }
                    }
                }
            `,
            variables: { id },
            mightContainPrivateInfo: false,
        })
        .pipe(
            map(dataOrThrowErrors),
            map(data => data.node as GQL.ISavedSearch)
        )
}

export function createSavedSearch(
    description: string,
    query: string,
    notify: boolean,
    notifySlack: boolean,
    userId: Scalars['ID'] | null,
    orgId: Scalars['ID'] | null,
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<void> {
    return platformContext
        .requestGraphQL<CreateSavedSearchResult, CreateSavedSearchVariables>({
            request: gql`
                mutation CreateSavedSearch(
                    $description: String!
                    $query: String!
                    $notifyOwner: Boolean!
                    $notifySlack: Boolean!
                    $userID: ID
                    $orgID: ID
                ) {
                    createSavedSearch(
                        description: $description
                        query: $query
                        notifyOwner: $notifyOwner
                        notifySlack: $notifySlack
                        userID: $userID
                        orgID: $orgID
                    ) {
                        ...SavedSearchFields
                    }
                }
                ${savedSearchFragment}
            `,
            variables: {
                description,
                query,
                notifyOwner: notify,
                notifySlack,
                userID: userId,
                orgID: orgId,
            },
            mightContainPrivateInfo: true,
        })
        .pipe(
            map(dataOrThrowErrors),
            map(() => undefined)
        )
}

export function updateSavedSearch(
    id: Scalars['ID'],
    description: string,
    query: string,
    notify: boolean,
    notifySlack: boolean,
    userId: Scalars['ID'] | null,
    orgId: Scalars['ID'] | null,
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<void> {
    return platformContext
        .requestGraphQL<UpdateSavedSearchResult, UpdateSavedSearchVariables>({
            request: gql`
                mutation UpdateSavedSearch(
                    $id: ID!
                    $description: String!
                    $query: String!
                    $notifyOwner: Boolean!
                    $notifySlack: Boolean!
                    $userID: ID
                    $orgID: ID
                ) {
                    updateSavedSearch(
                        id: $id
                        description: $description
                        query: $query
                        notifyOwner: $notifyOwner
                        notifySlack: $notifySlack
                        userID: $userID
                        orgID: $orgID
                    ) {
                        ...SavedSearchFields
                    }
                }
                ${savedSearchFragment}
            `,
            variables: {
                id,
                description,
                query,
                notifyOwner: notify,
                notifySlack,
                userID: userId,
                orgID: orgId,
            },
            mightContainPrivateInfo: true,
        })
        .pipe(
            map(dataOrThrowErrors),
            map(() => undefined)
        )
}

export function deleteSavedSearch(
    id: Scalars['ID'],
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<void> {
    return platformContext
        .requestGraphQL<DeleteSavedSearchResult, DeleteSavedSearchVariables>({
            request: gql`
                mutation DeleteSavedSearch($id: ID!) {
                    deleteSavedSearch(id: $id) {
                        alwaysNil
                    }
                }
            `,
            variables: { id },
            mightContainPrivateInfo: false,
        })
        .pipe(
            map(dataOrThrowErrors),
            map(() => undefined)
        )
}

export const highlightCode = memoizeObservable(
    ({
        platformContext,
        ...context
    }: {
        code: string
        fuzzyLanguage: string
        disableTimeout: boolean
        platformContext: Pick<PlatformContext, 'requestGraphQL'>
    }): Observable<string> =>
        platformContext
            .requestGraphQL<highlightCodeResult, highlightCodeVariables>({
                request: gql`
                    query highlightCode($code: String!, $fuzzyLanguage: String!, $disableTimeout: Boolean!) {
                        highlightCode(code: $code, fuzzyLanguage: $fuzzyLanguage, disableTimeout: $disableTimeout)
                    }
                `,
                variables: context,
                mightContainPrivateInfo: true,
            })
            .pipe(
                map(({ data, errors }) => {
                    if (!data || !data.highlightCode) {
                        throw createAggregateError(errors)
                    }
                    return data.highlightCode
                })
            ),
    context => `${context.code}:${context.fuzzyLanguage}:${String(context.disableTimeout)}`
)

export interface EventLogResult {
    totalCount: number
    nodes: { argument: string | null; timestamp: string; url: string }[]
    pageInfo: { hasNextPage: boolean }
}

function fetchEvents(
    userId: Scalars['ID'],
    first: number,
    eventName: string,
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<EventLogResult | null> {
    if (!userId) {
        return of(null)
    }

    const result = platformContext.requestGraphQL<EventLogsDataResult, EventLogsDataVariables>({
        request: gql`
            query EventLogsData($userId: ID!, $first: Int, $eventName: String!) {
                node(id: $userId) {
                    ... on User {
                        __typename
                        eventLogs(first: $first, eventName: $eventName) {
                            nodes {
                                argument
                                timestamp
                                url
                            }
                            pageInfo {
                                hasNextPage
                            }
                            totalCount
                        }
                    }
                }
            }
        `,
        variables: { userId, first: first ?? null, eventName },
        mightContainPrivateInfo: true,
    })

    return result.pipe(
        map(dataOrThrowErrors),
        map(
            (data: EventLogsDataResult): EventLogResult => {
                if (!data.node || data.node.__typename !== 'User') {
                    throw new Error('User not found')
                }
                return data.node.eventLogs
            }
        )
    )
}

export function fetchRecentSearches(
    userId: Scalars['ID'],
    first: number,
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<EventLogResult | null> {
    return fetchEvents(userId, first, 'SearchResultsQueried', platformContext)
}

export function fetchRecentFileViews(
    userId: Scalars['ID'],
    first: number,
    platformContext: Pick<PlatformContext, 'requestGraphQL'>
): Observable<EventLogResult | null> {
    return fetchEvents(userId, first, 'ViewBlob', platformContext)
}
