declare module 'jsvectormap' {
  interface JsVectorMapOptions {
    selector: HTMLElement | string;
    map: string;
    backgroundColor?: string;
    draggable?: boolean;
    zoomButtons?: boolean;
    zoomOnScroll?: boolean;
    zoomOnScrollSpeed?: number;
    zoomMax?: number;
    zoomMin?: number;
    showTooltip?: boolean;
    regionStyle?: {
      initial?: Record<string, unknown>;
      hover?: Record<string, unknown>;
      selected?: Record<string, unknown>;
    };
    markerStyle?: {
      initial?: Record<string, unknown>;
      hover?: Record<string, unknown>;
      selected?: Record<string, unknown>;
    };
    markers?: Array<{
      name: string;
      coords: [number, number];
      style?: Record<string, unknown>;
    }>;
    onMarkerTooltipShow?: (tooltip: { text: () => string; selector: { innerHTML: string } }, index: number) => void;
  }

  export default class JsVectorMap {
    constructor(options: JsVectorMapOptions);
    destroy(): void;
    addMarkers(markers: Array<{ name: string; coords: [number, number]; style?: Record<string, unknown> }>): void;
    removeMarkers(): void;
  }
}

declare module 'jsvectormap/dist/maps/world' {}
declare module 'jsvectormap/dist/jsvectormap.css' {}
