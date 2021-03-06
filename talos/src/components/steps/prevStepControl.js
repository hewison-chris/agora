import React from 'react';
import { steps } from "./static"

import { withAppState } from "../app/State"

import ButtonToPreviewLink from "../preview/buttonToPreviewLink"
import ButtonToPrevStep from "../items/controls/buttonToPrevStep"
import PrevButton from "../items/static/prevButton"

const PrevStepControl = props => {
  const { currentIndex } = props

  switch (currentIndex) {
    case steps.secretSeed:
      return <ButtonToPreviewLink>
        <PrevButton>Previous</PrevButton>
      </ButtonToPreviewLink>

    default:
      return <ButtonToPrevStep>
        <PrevButton>Previous</PrevButton>
      </ButtonToPrevStep>
  }

}

export default withAppState(PrevStepControl)
