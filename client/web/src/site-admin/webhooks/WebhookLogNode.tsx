import { format } from 'date-fns'
import ChevronDownIcon from 'mdi-react/ChevronDownIcon'
import ChevronRightIcon from 'mdi-react/ChevronRightIcon'
import React, { useCallback, useState } from 'react'

import { Tab, TabList, TabPanel, TabPanels, Tabs } from '@sourcegraph/wildcard'

import { WebhookLogFields } from '../../graphql-operations'

import { MessagePanel } from './MessagePanel'
import { StatusCode } from './StatusCode'
import styles from './WebhookLogNode.module.scss'

export interface Props {
    node: WebhookLogFields
}

export const WebhookLogNode: React.FunctionComponent<Props> = ({
    node: { externalService, receivedAt, request, response, statusCode },
}) => {
    const [isExpanded, setIsExpanded] = useState(false)
    const toggleExpanded = useCallback(() => setIsExpanded(!isExpanded), [isExpanded])

    return (
        <>
            <span className={styles.separator} />
            <span>
                <button
                    type="button"
                    className="btn btn-icon"
                    aria-label={isExpanded ? 'Collapse section' : 'Expand section'}
                    onClick={toggleExpanded}
                >
                    {isExpanded ? (
                        <ChevronDownIcon className="icon-inline" aria-label="Close section" />
                    ) : (
                        <ChevronRightIcon className="icon-inline" aria-label="Expand section" />
                    )}
                </button>
            </span>
            <span className="text-center">
                <StatusCode code={statusCode} />
            </span>
            <span>
                {externalService ? externalService.displayName : <span className="text-danger">Unmatched</span>}
            </span>
            <span className={styles.receivedAt}>{format(Date.parse(receivedAt), 'Ppp')}</span>
            {isExpanded && (
                <div className={styles.expanded}>
                    <Tabs size="small">
                        <TabList>
                            <Tab>Request</Tab>
                            <Tab>Response</Tab>
                        </TabList>
                        <TabPanels>
                            <TabPanel>
                                <MessagePanel
                                    className={styles.tabPanel}
                                    message={request}
                                    requestOrStatusCode={request}
                                />
                            </TabPanel>
                            <TabPanel>
                                <MessagePanel
                                    className={styles.tabPanel}
                                    message={response}
                                    requestOrStatusCode={statusCode}
                                />
                            </TabPanel>
                        </TabPanels>
                    </Tabs>
                </div>
            )}
        </>
    )
}