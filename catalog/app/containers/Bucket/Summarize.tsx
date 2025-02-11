import type { S3 } from 'aws-sdk'
import cx from 'classnames'
import type { LocationDescriptor } from 'history'
import * as R from 'ramda'
import * as React from 'react'
import * as M from '@material-ui/core'

import { copyWithoutSpaces } from 'components/BreadCrumbs'
import ButtonIconized from 'components/ButtonIconized'
import Markdown from 'components/Markdown'
import * as Preview from 'components/Preview'
import type { Type as SummaryFileTypes } from 'components/Preview/loaders/summarize'
import Skeleton, { SkeletonProps } from 'components/Skeleton'
import { docs } from 'constants/urls'
import * as APIConnector from 'utils/APIConnector'
import * as AWS from 'utils/AWS'
import { useData } from 'utils/Data'
import * as LogicalKeyResolver from 'utils/LogicalKeyResolver'
import * as NamedRoutes from 'utils/NamedRoutes'
import Link from 'utils/StyledLink'
import { PackageHandle } from 'utils/packageHandle'
import * as s3paths from 'utils/s3paths'

import * as requests from './requests'
import * as errors from './errors'

interface S3Handle extends LogicalKeyResolver.S3SummarizeHandle {
  error?: errors.BucketError
}

interface SummarizeFile {
  description?: string
  handle: S3Handle
  path: string
  title?: string
  types?: SummaryFileTypes
  width?: string | number
  expand?: boolean
}

type MakeURL = (h: S3Handle) => LocationDescriptor

enum FileThemes {
  Overview = 'overview',
  Nested = 'nested',
}
const FileThemeContext = React.createContext(FileThemes.Overview)

const useSectionStyles = M.makeStyles((t) => ({
  root: {
    position: 'relative',
    [t.breakpoints.down('xs')]: {
      borderRadius: 0,
    },
    [t.breakpoints.up('sm')]: {
      marginTop: t.spacing(2),
    },
  },
  [FileThemes.Overview]: {
    [t.breakpoints.down('xs')]: {
      padding: t.spacing(2),
      paddingTop: t.spacing(3),
    },
    [t.breakpoints.up('sm')]: {
      padding: t.spacing(4),
    },
  },
  [FileThemes.Nested]: {
    [t.breakpoints.down('xs')]: {
      padding: t.spacing(1),
      paddingTop: t.spacing(2),
    },
    [t.breakpoints.up('sm')]: {
      padding: t.spacing(2),
    },
  },
  description: {
    ...t.typography.body2,
  },
  heading: {
    ...t.typography.h6,
    display: 'flex',
    lineHeight: 1.75,
    marginBottom: t.spacing(1),
    [t.breakpoints.up('sm')]: {
      marginBottom: t.spacing(2),
    },
    [t.breakpoints.up('md')]: {
      ...t.typography.h5,
    },
  },
  headingText: {
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  menu: {
    display: 'flex',
    marginLeft: t.spacing(1),
  },
  toggle: {
    marginLeft: 'auto',
  },
}))

interface SectionProps extends M.PaperProps {
  description?: React.ReactNode
  handle?: S3Handle
  heading?: React.ReactNode
  expanded?: boolean
  onToggle?: () => void
}

export function Section({
  handle,
  heading,
  description,
  children,
  expanded,
  onToggle,
  ...props
}: SectionProps) {
  const ft = React.useContext(FileThemeContext)
  const classes = useSectionStyles()
  return (
    <M.Paper className={cx(classes.root, classes[ft])} {...props}>
      {!!heading && (
        <div className={classes.heading}>
          <div className={classes.headingText}>{heading}</div>
          {onToggle && (
            <ButtonIconized
              className={classes.toggle}
              label={expanded ? 'Collapse' : 'Expand'}
              icon={expanded ? 'unfold_less' : 'unfold_more'}
              rotate={expanded}
              onClick={onToggle}
            />
          )}
          {handle && <Preview.Menu className={classes.menu} handle={handle} />}
        </div>
      )}
      {!!description && <div className={classes.description}>{description}</div>}
      {children}
    </M.Paper>
  )
}

interface PreviewBoxProps {
  children: React.ReactNode
  expanded?: boolean
  onToggle: () => void
}

const usePreviewBoxStyles = M.makeStyles((t) => ({
  root: {
    marginLeft: 'auto',
    marginRight: 'auto',
    maxHeight: t.spacing(30),
    minHeight: t.spacing(15),
    position: 'relative',

    // workarounds to speed-up notebook preview rendering:
    '&:not($expanded)': {
      // hide overflow only when not expanded, using this while expanded
      // slows down the page in chrome
      overflow: 'hidden',

      // only show 2 first cells unless expanded
      '& .ipynb-preview .cell:nth-child(n+3)': {
        display: 'none',
      },
    },
  },
  expanded: {
    maxHeight: 'none',
  },
  fade: {
    alignItems: 'flex-end',
    background: `linear-gradient(to top,
      rgba(255, 255, 255, 1),
      rgba(255, 255, 255, 0.9),
      rgba(255, 255, 255, 0.1),
      rgba(255, 255, 255, 0.1)
    )`,
    bottom: 0,
    display: 'flex',
    height: '100%',
    cursor: 'pointer',
    justifyContent: 'center',
    left: 0,
    position: 'absolute',
    width: '100%',
    zIndex: 1,
  },
}))

function PreviewBox({ children, expanded, onToggle }: PreviewBoxProps) {
  const classes = usePreviewBoxStyles()
  // TODO: Move expandable block to ExpandableBox and re-use for SearchResults
  // TODO: Listen firstElementNode ({children}) for resize
  //       if children height is smaller than box -> onToggle(force)
  return (
    <div className={cx(classes.root, { [classes.expanded]: expanded })}>
      {children}
      {!expanded && (
        <div className={classes.fade} onClick={onToggle} title="Click to expand" />
      )}
    </div>
  )
}

const CrumbLink = M.styled(Link)({ wordBreak: 'break-word' })

interface CrumbsProps {
  handle: S3Handle
}

function Crumbs({ handle }: CrumbsProps) {
  const { urls } = NamedRoutes.use()
  const crumbs = React.useMemo(() => {
    const all = s3paths.getBreadCrumbs(handle.key)
    const dirs = R.init(all).map(({ label, path }) => ({
      to: urls.bucketFile(handle.bucket, path),
      children: label,
    }))
    const file = {
      to: urls.bucketFile(handle.bucket, handle.key),
      children: R.last(all)?.label,
    }
    return { dirs, file }
  }, [handle.bucket, handle.key, urls])

  return (
    <span onCopy={copyWithoutSpaces}>
      {crumbs.dirs.map((c) => (
        <React.Fragment key={`crumb:${c.to}`}>
          <CrumbLink {...c} />
          &nbsp;/{' '}
        </React.Fragment>
      ))}
      <CrumbLink {...crumbs.file} />
    </span>
  )
}

interface FilePreviewProps {
  expanded?: boolean
  file?: SummarizeFile
  handle: S3Handle
  headingOverride: React.ReactNode
  packageHandle?: PackageHandle
}

export function FilePreview({
  expanded: defaultExpanded,
  file,
  handle,
  headingOverride,
  packageHandle,
}: FilePreviewProps) {
  const description = file?.description ? <Markdown data={file.description} /> : null
  const heading = headingOverride != null ? headingOverride : <Crumbs handle={handle} />

  const key = handle.logicalKey || handle.key
  const props = React.useMemo(() => Preview.getRenderProps(key, file), [key, file])

  const previewOptions = React.useMemo(
    () => ({
      ...file,
      context: Preview.CONTEXT.LISTING,
    }),
    [file],
  )
  const previewHandle = React.useMemo(
    () => ({ ...handle, packageHandle }),
    [handle, packageHandle],
  )

  const [expanded, setExpanded] = React.useState(defaultExpanded)
  const onToggle = React.useCallback(() => setExpanded((e) => !e), [])
  const renderContents = React.useCallback(
    (children) => <PreviewBox {...{ children, expanded, onToggle }} />,
    [expanded, onToggle],
  )

  // TODO: check for glacier and hide items
  return (
    <Section
      description={description}
      heading={heading}
      handle={handle}
      expanded={expanded}
      onToggle={onToggle}
    >
      {Preview.load(
        previewHandle,
        Preview.display({
          renderContents,
          renderProgress: () => <ContentSkel />,
          props,
        }),
        previewOptions,
      )}
    </Section>
  )
}

function ContentSkel({ lines = 15, ...props }) {
  const widths = React.useMemo(
    () => R.times(() => 80 + Math.random() * 20, lines),
    [lines],
  )
  return (
    <M.Box {...props}>
      {widths.map((w, i) => (
        <Skeleton
          // eslint-disable-next-line react/no-array-index-key
          key={i}
          height={16}
          width={`${w}%`}
          borderRadius="borderRadius"
          mt={i ? 1 : 0}
        />
      ))}
    </M.Box>
  )
}

export const HeadingSkel = (props: SkeletonProps) => (
  <Skeleton borderRadius="borderRadius" width={200} {...props}>
    &nbsp;
  </Skeleton>
)

export const FilePreviewSkel = () => (
  <Section heading={<HeadingSkel />}>
    <ContentSkel />
  </Section>
)

function getDisplayName(handle: S3Handle): string {
  // TODO: show crumbs for packages too
  return s3paths.getBasename(handle.key)
}

function useFileUrl(handle: S3Handle, mkUrl?: MakeURL): LocationDescriptor {
  const { urls } = NamedRoutes.use()
  return React.useMemo(
    () => (mkUrl ? mkUrl(handle) : urls.bucketFile(handle.bucket, handle.key)),
    [handle, mkUrl, urls],
  )
}

interface TitleCustomProps {
  handle: S3Handle
  mkUrl?: MakeURL
  title: React.ReactNode
}

function TitleCustom({ title, mkUrl, handle }: TitleCustomProps) {
  const displayName = getDisplayName(handle)
  const url = useFileUrl(handle, mkUrl)

  return (
    <Link title={displayName} to={url}>
      {title}
    </Link>
  )
}

interface TitleFilenameProps {
  handle: S3Handle
  mkUrl: MakeURL
}

function TitleFilename({ handle, mkUrl }: TitleFilenameProps) {
  const displayName = getDisplayName(handle)
  const url = useFileUrl(handle, mkUrl)

  return <Link to={url}>{displayName}</Link>
}

function getHeadingOverride(file: SummarizeFile, mkUrl?: MakeURL) {
  if (file.title)
    return <TitleCustom handle={file.handle} title={file.title} mkUrl={mkUrl} />
  if (mkUrl) return <TitleFilename handle={file.handle} mkUrl={mkUrl} />
  return null
}

interface EnsureAvailabilityProps {
  s3: S3
  handle: S3Handle
  children: () => React.ReactNode
}

function EnsureAvailability({ s3, handle, children }: EnsureAvailabilityProps) {
  return useData(requests.ensureObjectIsPresent, { s3, ...handle }).case({
    _: () => null,
    Ok: (h: unknown) => !!h && children(),
  })
}

interface FileHandleProps {
  file: SummarizeFile
  mkUrl?: MakeURL
  s3: S3
  packageHandle?: PackageHandle
}

function FileHandle({ file, mkUrl, packageHandle, s3 }: FileHandleProps) {
  if (file.handle.error)
    return (
      <Section heading={file.handle.key}>
        Unable to resolve path: "{s3paths.handleToS3Url(file.handle)}"
      </Section>
    )

  return (
    <EnsureAvailability s3={s3} handle={file.handle}>
      {() => (
        <FilePreview
          handle={file.handle}
          headingOverride={getHeadingOverride(file, mkUrl)}
          file={file}
          expanded={file.expand}
          packageHandle={packageHandle}
        />
      )}
    </EnsureAvailability>
  )
}

const SUMMARY_ENTRIES = 7

function getColumnStyles(width?: number | string) {
  if (typeof width === 'string') return { flexBasis: width }
  if (R.is(Number, width)) return { flexGrow: width }
  return { flexGrow: 1 }
}

interface ColumnProps {
  className: string
  file: SummarizeFile
  mkUrl?: MakeURL
  s3: S3
  packageHandle?: PackageHandle
}

function Column({ className, file, mkUrl, packageHandle, s3 }: ColumnProps) {
  const style = React.useMemo(() => getColumnStyles(file.width), [file.width])
  return (
    <div className={className} style={style}>
      <FileHandle file={file} mkUrl={mkUrl} packageHandle={packageHandle} s3={s3} />
    </div>
  )
}

const useRowStyles = M.makeStyles((t) => ({
  row: {
    marginLeft: t.spacing(-2),
    [t.breakpoints.up('sm')]: {
      display: 'flex',
      flexWrap: 'wrap',
      justifyContent: 'space-between',
    },
  },
  column: {
    marginLeft: t.spacing(2),
  },
}))

interface RowProps {
  file: SummarizeFile
  mkUrl?: MakeURL
  s3: S3
  packageHandle?: PackageHandle
}

function Row({ file, mkUrl, packageHandle, s3 }: RowProps) {
  const classes = useRowStyles()

  if (!Array.isArray(file))
    return <FileHandle file={file} s3={s3} mkUrl={mkUrl} packageHandle={packageHandle} />

  return (
    <div className={classes.row}>
      {file.map((f) => (
        <Column
          className={classes.column}
          file={f}
          key={`${f.handle.bucket}/${f.handle.key}`}
          mkUrl={mkUrl}
          s3={s3}
        />
      ))}
    </div>
  )
}

const useSummaryEntriesStyles = M.makeStyles((t) => ({
  root: {
    position: 'relative',
    zIndex: 1,
  },
  more: {
    display: 'flex',
    justifyContent: 'center',
    marginTop: t.spacing(2),
  },
}))

interface SummaryEntriesProps {
  entries: SummarizeFile[]
  mkUrl?: MakeURL
  s3: S3
  packageHandle?: PackageHandle
}

function SummaryEntries({ entries, mkUrl, packageHandle, s3 }: SummaryEntriesProps) {
  const classes = useSummaryEntriesStyles()
  const [shown, setShown] = React.useState(SUMMARY_ENTRIES)
  const showMore = React.useCallback(() => {
    setShown(R.add(SUMMARY_ENTRIES))
  }, [setShown])

  const shownEntries = R.take(shown, entries)
  return (
    <div className={classes.root}>
      {shownEntries.map((file, i) => (
        <Row
          key={`${
            Array.isArray(file) ? file.map((f) => f.handle.key).join('') : file.handle.key
          }_${i}`}
          file={file}
          mkUrl={mkUrl}
          packageHandle={packageHandle}
          s3={s3}
        />
      ))}
      {shown < entries.length && (
        <div className={classes.more}>
          <M.Button variant="contained" color="primary" onClick={showMore}>
            Show more
          </M.Button>
        </div>
      )}
    </div>
  )
}

interface SummaryRootProps {
  s3: S3
  bucket: string
  inStack: boolean
  overviewUrl: string
}

export function SummaryRoot({ s3, bucket, inStack, overviewUrl }: SummaryRootProps) {
  const req = APIConnector.use()
  const data = useData(requests.bucketSummary, { req, s3, bucket, inStack, overviewUrl })
  return (
    <FileThemeContext.Provider value={FileThemes.Overview}>
      {data.case({
        Err: (e: Error) => {
          // eslint-disable-next-line no-console
          console.warn('Error loading summary')
          // eslint-disable-next-line no-console
          console.error(e)
          return null
        },
        Ok: (entries: SummarizeFile[]) => <SummaryEntries entries={entries} s3={s3} />,
        Pending: () => <FilePreviewSkel />,
        _: () => null,
      })}
    </FileThemeContext.Provider>
  )
}

interface SummaryFailedProps {
  error: Error
}

const useSummaryFailedStyles = M.makeStyles((t) => ({
  heading: {
    color: t.palette.error.light,
    display: 'flex',
    alignItems: 'center',
  },
  icon: {
    marginRight: t.spacing(1),
  },
}))

function SummaryFailed({ error }: SummaryFailedProps) {
  const classes = useSummaryFailedStyles()
  return (
    <Section
      heading={
        <span className={classes.heading} title={error.message}>
          <M.Icon className={classes.icon}>error</M.Icon>Oops
        </span>
      }
    >
      <M.Typography>Check your quilt_summarize.json file for errors.</M.Typography>
      <M.Typography>
        See the{' '}
        <Link href={`${docs}/catalog/visualizationdashboards#quilt_summarize.json`}>
          summarize docs
        </Link>{' '}
        for more.
      </M.Typography>
    </Section>
  )
}

interface SummaryNestedProps {
  mkUrl: MakeURL
  handle: {
    key: string
    logicalKey: string
    bucket: string
    version: string
    etag: string
  }
  packageHandle: PackageHandle
}

export function SummaryNested({ handle, mkUrl, packageHandle }: SummaryNestedProps) {
  const s3 = AWS.S3.use()
  const resolveLogicalKey = LogicalKeyResolver.use()
  const data = useData(requests.summarize, { s3, handle, resolveLogicalKey })
  return (
    <FileThemeContext.Provider value={FileThemes.Nested}>
      {data.case({
        Err: (e: Error) => <SummaryFailed error={e} />,
        Ok: (entries: SummarizeFile[]) => (
          <SummaryEntries
            entries={entries}
            s3={s3}
            mkUrl={mkUrl}
            packageHandle={packageHandle}
          />
        ),
        Pending: () => <FilePreviewSkel />,
        _: () => null,
      })}
    </FileThemeContext.Provider>
  )
}
