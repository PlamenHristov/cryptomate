import {helloWorld, goodBye} from "../src"
import npmPackage from "../src/index"

describe("NPM Package", () => {
  it("should be an object", () => {
    expect(npmPackage).toBeDefined()
  })

  it("should have a helloWorld property", () => {
    expect(npmPackage).toHaveProperty("helloWorld")
  })
})

describe("Hello World Function", () => {

  it("should return the hello world message", () => {
    const expected = "Hello World from my example modern npm package!"
    expect(helloWorld()).toEqual(expected)
  })
})

describe("Goodbye Function", () => {
  it("should return the goodbye message", () => {
    const expected = "Goodbye from my example modern npm package!"
    expect(goodBye()).toEqual(expected)
  })
})