// Copyright 2019 Qubit Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/go-github/v22/github"
)

func (ws *workflowSyncer) webhookCheckSuite(ctx context.Context, event *github.CheckSuiteEvent) (int, string) {
	ghClient, err := ws.ghClientSrc.getClient(int(*event.Installation.ID))
	if err != nil {
		return http.StatusBadRequest, err.Error()
	}

	wf, err := ws.getWorkflow(
		ctx,
		ghClient,
		*event.Org.Login,
		*event.Repo.Name,
		*event.CheckSuite.HeadSHA,
		ws.config.CIFilePath,
	)

	if os.IsNotExist(err) {
		log.Printf("no %s in %s/%s (%s)",
			ws.config.CIFilePath,
			*event.Org.Login,
			*event.Repo.Name,
			*event.CheckSuite.HeadSHA,
		)
		return http.StatusOK, ""
	}

	if err != nil {
		msg := fmt.Sprintf("unable to parse workflow, %v", err)
		status := "completed"
		conclusion := "failure"
		title := "Workflow Setup"
		_, _, err := ghClient.Checks.CreateCheckRun(ctx,
			*event.Org.Login,
			*event.Repo.Name,
			github.CreateCheckRunOptions{
				Name:       "Argo Workflow",
				HeadBranch: *event.CheckSuite.HeadBranch,
				HeadSHA:    *event.CheckSuite.HeadSHA,
				Status:     &status,
				Conclusion: &conclusion,
				CompletedAt: &github.Timestamp{
					Time: time.Now(),
				},
				Output: &github.CheckRunOutput{
					Title:   &title,
					Summary: &msg,
				},
			},
		)
		if err != nil {
			log.Printf("failed to create CR, %v", err)
		}
		return http.StatusBadRequest, msg
	}

	cr, _, err := ghClient.Checks.CreateCheckRun(ctx,
		*event.Org.Login,
		*event.Repo.Name,
		github.CreateCheckRunOptions{
			Name:       "Argo Workflow",
			HeadBranch: *event.CheckSuite.HeadBranch,
			HeadSHA:    *event.CheckSuite.HeadSHA,
		},
	)
	if err != nil {
		log.Printf("Unable to create check run, %v", err)
		return http.StatusInternalServerError, ""
	}

	wf = wf.DeepCopy()
	ws.updateWorkflow(wf, event, cr)
	_, err = ws.client.Argoproj().Workflows("argo").Create(wf)
	if err != nil {
		msg := fmt.Sprintf("argo workflow creation failed, %v", err)
		log.Print(msg)
		status := "completed"
		conclusion := "failure"
		_, _, err = ghClient.Checks.UpdateCheckRun(
			ctx,
			*event.Org.Login,
			*event.Repo.Name,
			*cr.ID,
			github.UpdateCheckRunOptions{
				Status:     &status,
				Conclusion: &conclusion,
				Output: &github.CheckRunOutput{
					Summary: &msg,
				},
				CompletedAt: &github.Timestamp{
					Time: time.Now(),
				},
			})
		if err != nil {
			log.Printf("Update of aborted check run failed, %v", err)
		}

		return http.StatusInternalServerError, ""
	}

	return http.StatusOK, ""
}

func (ws *workflowSyncer) webhookCheckRunRequestAction(ctx context.Context, event *github.CheckRunEvent) (int, string) {
	ghClient, err := ws.ghClientSrc.getClient(int(*event.Installation.ID))
	if err != nil {
		return http.StatusBadRequest, err.Error()
	}

	/*
			// All is good (return an error to fail)
			ciFile := ".kube-ci/deploy.yaml"

			wf, err := ws.getWorkflow(
				ctx,
				ghClient,
				*event.Org.Login,
				*event.Repo.Name,
				*event.CheckRun.HeadSHA,
				ciFile,
			)

		if os.IsNotExist(err) {
			log.Printf("no %s in %s/%s (%s)",
				ciFile,
				*event.Org.Login,
				*event.Repo.Name,
				*event.CheckRun.HeadSHA,
			)
			return http.StatusOK, ""
		}
	*/

	env := "staging"
	msg := fmt.Sprintf("deploying the thing to %v", env)
	dep, _, err := ghClient.Repositories.CreateDeployment(
		ctx,
		*event.Org.Login,
		*event.Repo.Name,
		&github.DeploymentRequest{
			Ref:         event.CheckRun.HeadSHA,
			Description: &msg,
			Environment: &env,
		},
	)

	if err != nil {
		log.Printf("create deployment ailed, %v", err)
		return http.StatusInternalServerError, ""
	}

	log.Printf("Deployment created, %v", *dep.ID)

	return http.StatusOK, "blah"
}
