/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListResourcesVariables = {
  input?: Types.Maybe<Types.ListResourcesInput>;
};

export type ListResources = {
  resources?: Types.Maybe<{
    resources?: Types.Maybe<
      Array<
        Types.Maybe<
          Pick<
            Types.ResourceSummary,
            'lastModified' | 'type' | 'integrationId' | 'complianceStatus' | 'id'
          >
        >
      >
    >;
    paging?: Types.Maybe<Pick<Types.PagingData, 'totalPages' | 'thisPage' | 'totalItems'>>;
  }>;
  integrations?: Types.Maybe<Array<Pick<Types.Integration, 'integrationLabel' | 'integrationId'>>>;
};

export const ListResourcesDocument = gql`
  query ListResources($input: ListResourcesInput) {
    resources(input: $input) {
      resources {
        lastModified
        type
        integrationId
        complianceStatus
        id
      }
      paging {
        totalPages
        thisPage
        totalItems
      }
    }
    integrations(input: { integrationType: "aws-scan" }) {
      integrationLabel
      integrationId
    }
  }
`;

/**
 * __useListResources__
 *
 * To run a query within a React component, call `useListResources` and pass it any options that fit your needs.
 * When your component renders, `useListResources` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListResources({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useListResources(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListResources, ListResourcesVariables>
) {
  return ApolloReactHooks.useQuery<ListResources, ListResourcesVariables>(
    ListResourcesDocument,
    baseOptions
  );
}
export function useListResourcesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListResources, ListResourcesVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListResources, ListResourcesVariables>(
    ListResourcesDocument,
    baseOptions
  );
}
export type ListResourcesHookResult = ReturnType<typeof useListResources>;
export type ListResourcesLazyQueryHookResult = ReturnType<typeof useListResourcesLazyQuery>;
export type ListResourcesQueryResult = ApolloReactCommon.QueryResult<
  ListResources,
  ListResourcesVariables
>;
