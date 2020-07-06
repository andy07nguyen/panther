package models

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

import "time"

const (
	// RuleType identifies the Alert to be for a Policy
	RuleType = "RULE"

	// PolicyType identifies the Alert to be for a Policy
	PolicyType = "POLICY"
)

// Alert is the schema for each row in the Dynamo alerts table.
type Alert struct {
	// ID is the rule that triggered the alert.
	AnalysisID string `json:"analysisId" validate:"required"`

	// Type specifies if an alert is for a policy or a rule
	Type string `json:"type" validate:"oneof=RULE POLICY"`

	// CreatedAt is the creation timestamp (seconds since epoch).
	CreatedAt time.Time `json:"createdAt" validate:"required"`

	// Severity is the alert severity at the time of creation.
	Severity string `json:"severity" validate:"oneof=INFO LOW MEDIUM HIGH CRITICAL"`

	// OutputIDs is the set of outputs for this alert.
	OutputIDs []string `json:"outputIds,omitempty"`

	// AnalysisDescription is the description of the rule that triggered the alert.
	AnalysisDescription *string `json:"analysisDescription,omitempty"`

	// Name is the name of the policy at the time the alert was triggered.
	AnalysisName *string `json:"analysisName,omitempty"`

	// Version is the S3 object version for the policy.
	Version *string `json:"version,omitempty"`

	// Runbook is the user-provided triage information.
	Runbook *string `json:"runbook,omitempty"`

	// Status is the user-provided status level. An empty value means the user has not set the status.
	Status string `json:"status" validate:"omitempty,oneof=OPEN TRIAGED CLOSED RESOLVED"`

	// Tags is the set of policy tags.
	Tags []string `json:"tags,omitempty"`

	// AlertID specifies the alertId that this Alert is associated with.
	AlertID *string `json:"alertId,omitempty"`

	// Title is the optional title for the alert generated by Python Rules engine
	Title *string `json:"title,omitempty"`
}
