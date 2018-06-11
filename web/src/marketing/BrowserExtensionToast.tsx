import * as React from 'react'
import { Subscription } from 'rxjs'
import { browserExtensionInstalled } from '../tracking/analyticsUtils'
import { eventLogger } from '../tracking/eventLogger'
import { showDotComMarketing } from '../util/features'
import { Toast } from './Toast'
import { daysActiveCount } from './util'

const CHROME_EXTENSION_STORE_LINK = 'https://chrome.google.com/webstore/detail/dgjhfomjieaadpoljlnidmbgkdffpack'
const FIREFOX_EXTENSION_STORE_LINK = 'https://addons.mozilla.org/en-US/firefox/addon/sourcegraph/'
const HAS_DISMISSED_TOAST_KEY = 'has-dismissed-browser-ext-toast'

declare global {
    interface Window {
        chrome?: {
            webstore: {
                install: (link: string, success: () => void, error: (reason: string) => void) => void
            }
        }
    }
}

interface Props {
    browserLogoAsset: string
    browserName: string
    onClickInstall: () => void
}

interface State {
    visible: boolean
}

abstract class BrowserExtensionToast extends React.Component<Props, State> {
    private subscriptions = new Subscription()

    constructor(props: Props) {
        super(props)
        this.state = {
            visible: false,
        }
    }

    public componentDidMount(): void {
        // Display if we don't receive confirmation that the user already has
        // the extension installed within a short time.
        this.subscriptions.add(
            browserExtensionInstalled.subscribe(isInstalled => {
                const visible =
                    !isInstalled &&
                    showDotComMarketing &&
                    localStorage.getItem(HAS_DISMISSED_TOAST_KEY) !== 'true' &&
                    daysActiveCount === 1
                this.setState({ visible })
                if (visible) {
                    eventLogger.log('BrowserExtReminderViewed')
                }
            })
        )
    }

    public componentWillUnmount(): void {
        this.subscriptions.unsubscribe()
    }

    public render(): JSX.Element | null {
        if (!this.state.visible) {
            return null
        }

        return (
            <Toast
                icon={<img className="logo-icon" src={this.props.browserLogoAsset} />}
                title="Get Sourcegraph on GitHub"
                subtitle={`Get code intelligence while browsing GitHub and reading PRs with the Sourcegraph ${
                    this.props.browserName
                } extension`}
                cta={
                    <button type="button" className="btn btn-primary" onClick={this.onClickInstall}>
                        Install
                    </button>
                }
                onDismiss={this.onDismiss}
            />
        )
    }

    private onClickInstall = (): void => {
        this.props.onClickInstall()
        this.onDismiss()
    }

    private onDismiss = (): void => {
        localStorage.setItem(HAS_DISMISSED_TOAST_KEY, 'true')
        this.setState({ visible: false })
    }
}

export class ChromeExtensionToast extends React.Component {
    public render(): JSX.Element | null {
        return (
            <BrowserExtensionToast
                browserName="Chrome"
                browserLogoAsset="/.assets/img/logo-chrome.svg"
                onClickInstall={this.onClickInstall}
            />
        )
    }

    private onClickInstall = (): void => {
        eventLogger.log('BrowserExtInstallClicked', { marketing: { browser: 'Chrome' } })

        if (window.chrome) {
            window.chrome.webstore.install(
                CHROME_EXTENSION_STORE_LINK,
                () => this.onInstallExtensionSuccess(),
                () => this.onInstallExtensionFail()
            )
        } else {
            window.open(CHROME_EXTENSION_STORE_LINK, '_blank')
        }
    }

    /**
     * This function is invoked when inline installation successfully completes.
     * After the dialog is shown and the user agrees to add the item to Chrome.
     */
    private onInstallExtensionSuccess(): void {
        eventLogger.log('BrowserExtInstallSuccess')
    }

    /**
     * This function is invoked when inline installation does not successfully complete.
     * Possible reasons for this include the user canceling the dialog,
     * the linked item not being found in the store, or the install being initiated from a non-verified site.
     */
    private onInstallExtensionFail(): void {
        eventLogger.log('BrowserExtInstallFailed')
    }
}

export class FirefoxExtensionToast extends React.Component {
    public render(): JSX.Element | null {
        return (
            <BrowserExtensionToast
                browserName="Firefox"
                browserLogoAsset="/.assets/img/logo-firefox.svg"
                onClickInstall={this.onClickInstall}
            />
        )
    }

    private onClickInstall = (): void => {
        eventLogger.log('BrowserExtInstallClicked', { marketing: { browser: 'Firefox' } })
        window.open(FIREFOX_EXTENSION_STORE_LINK, '_blank')
    }
}
