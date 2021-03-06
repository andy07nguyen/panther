/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
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

import * as Types from '../../../__generated__/schema';

import gql from 'graphql-tag';

export type DestinationFull = { __typename: 'Destination' } & Pick<
  Types.Destination,
  | 'createdBy'
  | 'creationTime'
  | 'displayName'
  | 'lastModifiedBy'
  | 'lastModifiedTime'
  | 'outputId'
  | 'outputType'
  | 'verificationStatus'
  | 'defaultForSeverity'
> & {
    outputConfig: {
      slack?: Types.Maybe<Pick<Types.SlackConfig, 'webhookURL'>>;
      sns?: Types.Maybe<Pick<Types.SnsConfig, 'topicArn'>>;
      pagerDuty?: Types.Maybe<Pick<Types.PagerDutyConfig, 'integrationKey'>>;
      github?: Types.Maybe<Pick<Types.GithubConfig, 'repoName' | 'token'>>;
      jira?: Types.Maybe<
        Pick<
          Types.JiraConfig,
          'orgDomain' | 'projectKey' | 'userName' | 'apiKey' | 'assigneeId' | 'issueType'
        >
      >;
      opsgenie?: Types.Maybe<Pick<Types.OpsgenieConfig, 'apiKey'>>;
      msTeams?: Types.Maybe<Pick<Types.MsTeamsConfig, 'webhookURL'>>;
      sqs?: Types.Maybe<Pick<Types.SqsConfig, 'queueUrl'>>;
      asana?: Types.Maybe<Pick<Types.AsanaConfig, 'personalAccessToken' | 'projectGids'>>;
      customWebhook?: Types.Maybe<Pick<Types.CustomWebhookConfig, 'webhookURL'>>;
    };
  };

export const DestinationFull = gql`
  fragment DestinationFull on Destination {
    createdBy
    creationTime
    displayName
    lastModifiedBy
    lastModifiedTime
    outputId
    outputType
    outputConfig {
      slack {
        webhookURL
      }
      sns {
        topicArn
      }
      pagerDuty {
        integrationKey
      }
      github {
        repoName
        token
      }
      jira {
        orgDomain
        projectKey
        userName
        apiKey
        assigneeId
        issueType
      }
      opsgenie {
        apiKey
      }
      msTeams {
        webhookURL
      }
      sqs {
        queueUrl
      }
      asana {
        personalAccessToken
        projectGids
      }
      customWebhook {
        webhookURL
      }
    }
    verificationStatus
    defaultForSeverity
    __typename
  }
`;
