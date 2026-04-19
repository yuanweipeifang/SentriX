# Dashboard 日志横向条卡 Spec

## Why
当前 Dashboard 中间的事件日志块虽然已经可用，但视觉节奏仍不够规整，与参考图中的横向细长条模块存在明显差距。需要通过更明确的条卡样式、统一的高度和信息排布，提升中间主区的秩序感与可读性。

## What Changes
- 将 Dashboard 中间 `Event Stream` 区的日志项改为横向细长条卡片样式
- 统一日志条卡的高度、内边距、标题/副文案排版和状态点位置
- 约束日志条卡在不同屏宽下的换行、截断和纵向节奏，避免重新出现溢出或高低不齐
- 使日志列表整体风格更贴近参考图中的规则横向模块，而不是普通堆叠卡片

## Impact
- Affected specs: Dashboard 监控布局, 事件日志展示, 前端响应式布局
- Affected code: `frontend/src/components/panels/DashboardMonitor.tsx`, `frontend/src/App.css`

## ADDED Requirements
### Requirement: Dashboard 日志条卡样式
系统 SHALL 将 Dashboard 中间日志列表渲染为横向细长条卡片，使每条日志在视觉上形成统一、规整、可快速扫描的条带。

#### Scenario: 日志列表正常展示
- **WHEN** Dashboard 渲染事件日志列表
- **THEN** 每条日志应呈现为横向细长条卡片
- **AND** 条卡应具有统一高度和一致的左右内边距
- **AND** 状态点、标题和详情文本应沿同一视觉基线排布

### Requirement: 日志条卡内容约束
系统 SHALL 控制日志条卡内部文本的换行和截断行为，确保条卡在数据较长时仍保持规整，而不会撑破布局。

#### Scenario: 日志详情较长
- **WHEN** 日志详情文本长度超过单行可容纳宽度
- **THEN** 文本应按既定规则换行或截断
- **AND** 条卡高度应仍维持统一的视觉节奏
- **AND** 不得造成日志列表或周围模块溢出

### Requirement: 日志区与相邻模块对齐
系统 SHALL 保持日志列表与左侧底部信息区、右侧下半区模块在下半区的起始线、间距和模块节奏上的一致性。

#### Scenario: Dashboard 下半区整体观察
- **WHEN** 用户查看 Dashboard 红框区域
- **THEN** 左、中、右三列下半区应表现为统一的模块系统
- **AND** 日志列表条卡不应显得过高、过厚或与相邻模块节奏失衡

## MODIFIED Requirements
### Requirement: Dashboard 监控布局
系统 SHALL 在保留左侧导航、中间主区和右侧配置区三栏布局的前提下，使中间下半区日志块采用更接近参考图的横向细长条卡片样式，并保持整体响应式稳定。

## REMOVED Requirements
### Requirement: 普通堆叠日志卡片
**Reason**: 现有日志块更接近常规信息卡片，不符合用户要求的横向细长条视觉结构。
**Migration**: 将现有日志项样式迁移为统一高度、横向展开、信息密度更高的条卡布局，同时保留数据字段和交互入口。
