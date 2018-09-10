# Windows 8堆内部机理

## 简介

Windows 8开发者预览版在2011年九月发布。大多数人聚焦于操作系统的Metro UI，而我们决定调研一下内存管理器。尽管通用的堆exp已经消亡相当一段时间了，但对应用程序和底层操作系统内存管理器之间错综复杂的关系有一个深入的了解将大大提高在具体环境下的exp的可靠性。本文聚焦于Windows 7到Windows 8之间exp缓解措施的过渡，从用户空间到内核空间。我们将试验Windows内存管理器在分配、释放时内部做了哪些处理，我们也会找出Windows 8中所有新增的堆相关安全特性。同时，一些额外的技巧也会涉及，用于为读者提供相应的指示以便于达成更高级别的堆控制。

## 概览

本文分成两部分，每部分都有数个小节。第一部分主要是谈及用户空间堆管理，它是应用程序使用动态内存的默认机制。第一小节将对Windows 8堆管理器的数据结构的改变进行概述，随后对整个堆管理器架构的更新进行简述。第二小节则谈及分配和释放内存的关键算法。第三小节将揭露Windows 8上新的安全缓解措施，它们为动态分配内存提供了更好的全局保护。第四小节和最后一小节将揭示利用(exp)手法的详细信息。尽管在Windows 8预览版中有效的利用少得可怜。最后，我们将围绕整个用户空间堆管理器来进行总结。

第二部分内容会详述Windows 8的内核池分配器。在第一小节中，我们将简述内核池中的链表和数据结构。第二小节重点谈及了Windows 8内核池中新增的安全提升特性，诸如不可执行非分页池和内核池cookie。在第三小节中，我们将看到此前在Windows 7中可行的攻击手法是如何在Windows 8中被缓解措施阻断的。在第四小节，我们将讨论一些攻击Windows 8内核池的一些可替代手法，仍然聚焦于池头部攻击。最后的第五小节，我们会围绕整个内核池做一个汇总。

## 预研工作

尽管本文的内容是完全原创，但它也是基于旧知识所著。下面的列表包含了一些资料，我建议读者在看本文前预先研读这些资料。

- While some of the algorithms and data structures have changed for the Heap Manager, the underlying foundation is very similar to the Windows 7 Heap Manager (Valasek 2010)（尽管堆管理器的一些算法和数据结构有所改变，但底层机制和Windows 7堆管理器非常相似）
- Again, the vast majority of changes to the Kernel Pool were derived from the Windows 7 Kernel Pool which should be understood before digesting the follow material (Mandt 2011)（在消化下面的材料之前，需要先对Windows 7内核池的大量改动有一定理解）
- Lionel d’Hauenens (http://www.laboskopia.com) Symbol Type Viewer was an invaluable tool when analyzing the data structures used by the Windows 8 heap manager. Without it many hours might have been wasted looking for the proper structures.（Lionel d’Hauenens Symbol Type Viewer是一个无价之宝，可用于分析Widnows 8堆管理器的数据结构。如果没有它，那么势必将在寻找数据结构上浪费大量的时间）

## 先决条件

### 用户空间

所有的伪代码和数据结构都获取于Widnows 8 32位预览版的ntdll.dll(6.2.8400.0)，这也是该二进制最新的版本。显然，代码和数据受限于32位架构，但也和64位架构有一定关联。

如果你有什么问题，或是发现了本文的错误，请与Chris邮件联系(cvalasek@gmail.com)。

### 内核空间

所有的伪代码和数据结构都获取于Windows 8 64位预览版的ntoskrnl.exe(6.2.8400.0)。然而，为了找出缓解措施实现的不同，32位和64位都做了调研。在具体应用的地方会显式的提到。

如果你存在任何疑问，或是发现了什么错误，请与Tarjei邮件联系(kernelpool@gmail.com)。

## 术语

与以前的文章一样，本节用来避免在描述Windows 8堆对象和函数时存在任何的含糊其辞的术语。可能所用的术语无法与所有人达成一致，但贯穿整篇文章我们都将使用同一个约定的术语。

术语block或blocks指8字节或16字节连续的内存，两个大小分别所属于32位和64位架构。它是堆chunk头用于指示其大小所用的最基本的丈量单位。chunk是一片连续的内存，可以使用blocks或是bytes来丈量。

chunk头部或堆chunk头部与`_HEAP_ENTRY`结构是同义词。它们都可以与术语“头部”替代混用。

`_HEAP_LIST_LOOKUP`结构用于跟踪某一尺寸的空闲chunk，一般被称为`BlocksIndex`或是一个`ListLookup`。

`FreeList`是一个双向链表，它是`HeapBase`的一个成员，有一个指向链表中最小的chunk的头指针，后续的指针一路指向更大的chunk直到最后会指回自己，标志着链表的结束。另一方面，`ListHints`指向`FreeLists`的特定位置，作为一个搜索具体尺寸chunks的优化处理。

术语`UserBlocks`或`UserBlock container`用于描述独立的以`_HEAP_USERDATA_HEADER`先导的chunks集合。这些独立的chunks就是LFH返回给调用函数的内存空间。UserBlocks中的chunks由尺寸来组织在一起，或者是放置在`HeapBuckets`或`Buckets`中。

最后，`Bitmap`用于描述连续的一片内存空间，其中每个位表示一个状态，比如free或busy。

## 用户空间堆管理器

本节通过详述数据结构、算法以及安全机制等对Windows 8堆管理器的内部工作机制进行了调研。这并不意味着我们的工作尽善尽美，我们只是为Windows 8中最重要的概念提供了一个内视。

### 数据结构

下面的数据结构来自于Windows 8预览版，使用windbg对6.2.8400.0版本的ntdll.dll进行了数据摘取。当应用程序调用诸如free(), malloc()，realloc()等函数时，这些结构被用来跟踪和管理空闲/已分配内存。

#### _HEAP(HeapBase)

每个进程都会创建一个堆结构(默认进程堆)，也可以通过HeapCreate()创建额外的堆。它作为主体设施为动态内存相关条目提供服务，包括其他的结构体、指针以及堆管理器使用的数据，用于分配和释放内存。

完整的列表请在Windbg中使用dt _HEAP命令。

```
0:030> dt _HEAP
ntdll!_HEAP
+0x000 Entry : _HEAP_ENTRY
…
+0x018 Heap : Ptr32 _HEAP
…
+0x04c EncodeFlagMask : Uint4B
+0x050 Encoding : _HEAP_ENTRY
+0x058 Interceptor : Uint4B
…
+0x0b4 BlocksIndex : Ptr32 Void
…
+0x0c0 FreeLists : _LIST_ENTRY
+0x0c8 LockVariable : Ptr32 _HEAP_LOCK
+0x0cc CommitRoutine : Ptr32 long
+0x0d0 FrontEndHeap : Ptr32 Void
…
+0x0d8 FrontEndHeapUsageData : Ptr32 Uint2B
+0x0dc FrontEndHeapMaximumIndex : Uint2B
+0x0de FrontEndHeapStatusBitmap : [257] UChar
+0x1e0 Counters : _HEAP_COUNTERS
+0x23c TuningParameters : _HEAP_TUNING_PARAMETERS
```

- FrontEndHeap - 指向前端堆结构的指针。在Windows 8中，LFH是唯一的可选项。
- FrontEndHeapUsageData - 128个元素的16位整型数数组，用于表示计数器或是`HeapBucket`的索引。计数器指示了某个具体尺寸的分配数量，每次分配都会递增而释放时递减。HeapBucket索引为前端堆所用，判断哪一个`_HEAP_BUCKET`可以服务该请求。当后端管理器在处理分配和释放请求时，一旦为某一个具体尺寸启发式地激活了LFH，那么该HeapBucket索引值就在此时被更新。Windows 7此前将这些值保存在BlocksIndex内的ListHint[Size]->Blink变量中。
- FrontEndHeapStatusBitmap - 用于优化的位图，当处理内存请求时可以判断是由后端还是前端堆管理器来处理。如果位被置位那么LFH（前端堆）就会服务该请求，否则交给后端堆来处理。该值也是在后端管理器处理分配和释放请求时，启发式地为某个尺寸激活LFH时所设置。

#### _LFH_HEAP(Heap->FrontEndHeap)

`_LFH_HEAP`结构自Windows 7以来没有什么打的变化，只是regular InfoArrays和Affinitized InfoArrays被独立了出来。这意味着，与Windows 7不同的是，Windows 8不再使用LocalData成员来访问合适的基于处理器亲和性的`_HEAP_LOCAL_SEGMENT_INFO`结构，它使用分离出来的数组。

```
0:030> dt _LFH_HEAP
ntdll!_LFH_HEAP
+0x000 Lock : _RTL_SRWLOCK
+0x004 SubSegmentZones : _LIST_ENTRY
+0x00c Heap : Ptr32 Void
+0x010 NextSegmentInfoArrayAddress : Ptr32 Void
+0x014 FirstUncommittedAddress : Ptr32 Void
+0x018 ReservedAddressLimit : Ptr32 Void
+0x01c SegmentCreate : Uint4B
+0x020 SegmentDelete : Uint4B
+0x024 MinimumCacheDepth : Uint4B
+0x028 CacheShiftThreshold : Uint4B
+0x02c SizeInCache : Uint4B
+0x030 RunInfo : _HEAP_BUCKET_RUN_INFO
+0x038 UserBlockCache : [12] _USER_MEMORY_CACHE_ENTRY
+0x1b8 Buckets : [129] _HEAP_BUCKET
+0x3bc SegmentInfoArrays : [129] Ptr32 _HEAP_LOCAL_SEGMENT_INFO
+0x5c0 AffinitizedInfoArrays : [129] Ptr32 _HEAP_LOCAL_SEGMENT_INFO
+0x7c8 LocalData : [1] _HEAP_LOCAL_DATA
```

- SegmentInfoArrays - 当特定HeapBucket不存在亲和性关联时使用该数组。
- AffinitizedInfoArrays - 当特定处理器或核心为具体分配负责时使用该数组。可以了解一下SMP。

#### _HEAP_LOCAL_DATA(Heap->FrontEndHeap->LocalData)

#### _HEAP_LOCAL_SEGMENT_INFO(Heap->LFH->SegmentInfoArrays[] / AffinitizedInfoArrays[])

#### _HEAP_SUBSEGMENT(Heap->LFH->InfoArrays[]->ActiveSubsegment->UserBlocks)

#### _HEAP_ENTRY

### 架构

### 算法 - 分配

#### 中间物

#### 后端

#### 前端

### 算法-释放

#### 中间物

#### 后端

#### 前端

### 安全机制

#### _HEAP Handle保护

####虚拟内存随机化

#### 前端激活

#### 前端分配

#### 快速失败

#### 守护页

#### 任意释放

#### 异常处理

### 利用(Exp)战术

#### 位图翻转2.0

#### _HEAP_USERDATA_HEADER攻击

### 用户空间总结

## 内核池分配器

### 基本组件

#### 池类型

#### 池描述符

#### 池头部

### Windows 8增强

#### 不可执行非分页池(NX Non-Paged Pool)

#### 内核池Cookie

### 攻击缓解措施

#### 进程指针编码

#### Lookaside Cookie

#### 缓存对齐分配Cookie

#### 安全链入链出((Un)linking)

#### 总结

### 块尺寸攻击

#### 块尺寸攻击

#### 切割碎片攻击

### 内核空间总结

## 致谢

##参考文献