# DataHub OpenAPI Specification
[![Build Status](https://travis-ci.org/Accedian/datahub-api.svg?branch=master)](https://travis-ci.org/Accedian/datahub-api)

## Steps to update the documentation (needs to be done for skylight-api and datahub-api repos)
1. The spec/swagger.yaml will need to be updated with the latest Gather swagger.yaml. 
   To do this, go to the Gather master branch in adh-gather repo, and replace the ##### GATHER PATHS #####
   and ##### GATHER DEFINITIONS ##### portion with the latest one.
2. After this, go to the Accedian/stitchIt repo, and from the master branch get the latest openapi.yaml.
   Run the command:
   npx @redocly/cli build-docs openapi.yaml  
   This will generate a static html file. Edit the HTML file, if needed, to have the latest Release Date.
   For example, replace all instances of 23.08 with 23.11 - this is only necessary if the openapi.yaml 
   has not had any updates since the last release.
   Rename this file to session-stitchIt.html and replace the existing HTML file in 
   the skylight-api/web/ and datahub-api/web/ folder.
4. Repeat step 2 for Accedian/sensor-orchestrate (renaming it to agent-orchestration.html). 
4. For Capture-Orchestration, please go to https://console.cloud.google.com/storage/browser/pykouze-openapi 
   and download the HTML for the specific release date. Rename this file to capture-orchestration.html and place it in the web folder.
5. Once this is done, create the PR.

## Steps to finish

1. Enable [Travis](https://docs.travis-ci.com/user/getting-started/#To-get-started-with-Travis-CI%3A) for your repository (**note**: you already have `.travis.yml` file)
2. [Create GitHub access token](https://help.github.com/articles/creating-an-access-token-for-command-line-use/); check `public_repo` on `Select scopes` section.
3. Use the token value as a value for [Travis environment variable](https://docs.travis-ci.com/user/environment-variables/#Defining-Variables-in-Repository-Settings) with the name `GH_TOKEN`
4. Make a test commit to trigger CI: `git commit --allow-empty -m "Test Travis CI" && git push`
5. Wait until Travis build is finished. You can check progress by clicking on the `Build Status` badge at the top
6. If you did everything correct, https://accedian.github.io/datahub-api/ will lead to your new docs
7. **[Optional]** You can setup [custom domain](https://help.github.com/articles/using-a-custom-domain-with-github-pages/) (just create `web/CNAME` file)
8. Start writing/editing your OpenAPI spec: check out [usage](#usage) section below
9. **[Optional]** If you document public API consider adding it into [APIs.guru](https://APIs.guru) directory using [this form](https://apis.guru/add-api/).
10. Delete this section :smile:

## Links

- Documentation(ReDoc): https://accedian.github.io/datahub-api/
- SwaggerUI: https://accedian.github.io/datahub-api/swagger-ui/
- Look full spec:
    + JSON https://accedian.github.io/datahub-api/swagger.json
    + YAML https://accedian.github.io/datahub-api/swagger.yaml
- Preview spec version for branch `[branch]`: https://accedian.github.io/datahub-api/preview/[branch]

**Warning:** All above links are updated only after Travis CI finishes deployment

## Working on specification
### Install

1. Install [Node JS](https://nodejs.org/)
2. Clone repo and `cd`
    + Run `npm install`

### Usage

1. Run `npm start`
2. Checkout console output to see where local server is started. You can use all [links](#links) (except `preview`) by replacing https://accedian.github.io/datahub-api/ with url from the message: `Server started <url>`
3. Make changes using your favorite editor or `swagger-editor` (look for URL in console output)
4. All changes are immediately propagated to your local server, moreover all documentation pages will be automagically refreshed in a browser after each change
**TIP:** you can open `swagger-editor`, documentation and `swagger-ui` in parallel
5. Once you finish with the changes you can run tests using: `npm test`
6. Share you changes with the rest of the world by pushing to GitHub :smile
